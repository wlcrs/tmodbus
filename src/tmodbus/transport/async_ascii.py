"""Async ASCII Transport Layer Implementation.

Implements async Modbus ASCII protocol transport based on asyncio, including LRC processing.
"""

import asyncio
import logging
import time
from typing import TypedDict, TypeVar, Unpack

import serial_asyncio

from tmodbus.exceptions import (
    LRCError,
    InvalidResponseError,
    ModbusConnectionError,
    ModbusResponseError,
    ASCIIFrameError,
    error_code_to_exception_map,
)
from tmodbus.pdu import BaseModbusPDU, get_pdu_class
from tmodbus.utils.lrc import LRCModbus

from . import _format_bytes, raw_traffic_logger
from .async_base import AsyncBaseTransport

logger = logging.getLogger(__name__)
RT = TypeVar("RT")

DEFAULT_TIMEOUT = 10.0  # Default timeout in seconds for async operations

class PySerialOptions(TypedDict):
    """Options for the PySerial connection."""

    baudrate: int
    bytesize: int
    parity: str
    stopbits: float
    timeout: float | None
    xonxoff: bool
    rtscts: bool
    write_timeout: float | None
    dsrdtr: bool
    inter_byte_timeout: float | None

ASCII_FRAME_START = b':'
ASCII_FRAME_END = b'\r\n'
MAX_ASCII_FRAME_SIZE = 513  # 256 bytes (max RTU) * 2 + 1 for ':' + 2 for \r\n

def ascii_encode(data: bytes) -> bytes:
    """Encode binary data as ASCII hex, with upper-case letters."""
    return data.hex().upper().encode()

def ascii_decode(data: bytes) -> bytes:
    """Decode ASCII hex to binary data."""
    return bytes.fromhex(data.decode())

def build_ascii_frame(address: int, pdu: bytes) -> bytes:
    """Build a Modbus ASCII frame."""
    message = bytes([address]) + pdu
    lrc = LRCModbus.calculate(message)
    frame = ASCII_FRAME_START + ascii_encode(message + lrc) + ASCII_FRAME_END
    return frame

def parse_ascii_frame(frame: bytes) -> bytes:
    """Parse Modbus ASCII frame (strip start/end, decode hex, check LRC)."""
    if not frame.startswith(ASCII_FRAME_START) or not frame.endswith(ASCII_FRAME_END):
        raise ASCIIFrameError("Malformed ASCII frame", bytes_read=frame)
    # Remove ':' ... '\r\n'
    hex_payload = frame[1:-2]
    try:
        raw = ascii_decode(hex_payload)
    except Exception:
        raise ASCIIFrameError("Invalid hex in ASCII frame", bytes_read=frame)
    if len(raw) < 3:
        raise ASCIIFrameError("ASCII frame too short", bytes_read=frame)
    msg, lrc = raw[:-1], raw[-1:]
    if not LRCModbus.validate(msg + lrc):
        raise LRCError(bytes_read=frame)
    return raw  # address + pdu + lrc

class AsyncAsciiTransport(AsyncBaseTransport):
    """Async Modbus ASCII Transport Layer Implementation.

    Handles async Modbus Serial communication using the ASCII framing, LRC checking, and timeouts.
    """

    _reader: asyncio.StreamReader | None = None
    _writer: asyncio.StreamWriter | None = None
    _last_frame_end: float = 0.0
    _communication_lock: asyncio.Lock

    pyserial_options: PySerialOptions

    def __init__(
        self,
        port: str,
        **pyserial_options: Unpack[PySerialOptions],
    ) -> None:
        """Initialize async Serial transport layer for ASCII.

        Args:
            port: Target serial port (e.g., '/dev/ttyUSB0')
            pyserial_options: Additional PySerial options like baudrate, bytesize, parity, etc.
        """
        self.port = port
        self.pyserial_options = pyserial_options
        self.timeout = pyserial_options.get("timeout", DEFAULT_TIMEOUT)
        self._communication_lock = asyncio.Lock()

    async def open(self) -> None:
        """Establish Serial connection."""
        async with self._communication_lock:
            if self.is_open():
                logger.debug("Serial connection already open: %s", self.port)
                return

            try:
                self._reader, self._writer = await asyncio.wait_for(
                    serial_asyncio.open_serial_connection(
                        url=self.port,
                        **self.pyserial_options,
                    ),
                    timeout=self.pyserial_options.get("timeout", DEFAULT_TIMEOUT),
                )
                logger.info("Async Serial connection established to '%s'", self.port)

            except TimeoutError:
                raise
            except Exception as e:
                raise ModbusConnectionError from e

    async def close(self) -> None:
        """Close Serial connection."""
        async with self._communication_lock:
            if not self._writer:
                logger.debug("Serial connection already closed: %s", self.port)
                return

            try:
                self._writer.close()
                await self._writer.wait_closed()
                logger.info("Serial connection closed: %s", self.port)
            except Exception as e:
                logger.debug("Error during async connection close (ignorable): %s", e)
            finally:
                self._reader = None
                self._writer = None

    def is_open(self) -> bool:
        """Check Serial connection status."""
        if self._writer is None or self._reader is None:
            return False
        return not self._writer.is_closing()

    async def send_and_receive(self, unit_id: int, pdu: BaseModbusPDU[RT]) -> RT:
        """Async send PDU and receive response (ASCII mode).

        1. Build ASCII frame (':' + hex + LRC + '\r\n')
        2. Wait for end-of-frame gap (min 1 char time)
        3. Send request
        4. Receive frame
        5. Validate LRC/format
        6. Validate address, function code, error conditions
        7. Return response PDU
        """
        async with self._communication_lock:
            if not self.is_open():
                raise ModbusConnectionError("Not connected.")

            # 1. Build request frame
            request_pdu_bytes = pdu.encode_request()
            request_adu = build_ascii_frame(unit_id, request_pdu_bytes)

            raw_traffic_logger.debug("ASCII Send: %s", _format_bytes(request_adu))

            # 2. Wait for end-of-frame gap (1 char time minimum)
            # For simplicity, use 1ms
            time_since_last_frame = time.monotonic() - self._last_frame_end
            min_gap = 0.001
            if time_since_last_frame < min_gap:
                await asyncio.sleep(min_gap - time_since_last_frame)

            # 3. Send request
            if not self._writer:
                raise ModbusConnectionError("Connection not established.")
            self._writer.write(request_adu)
            await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)

            # 4. Receive response
            try:
                response_adu = await self._receive_response()
            except (ASCIIFrameError, ModbusConnectionError) as e:
                raw_traffic_logger.debug("ASCII Receive: %s [!]", _format_bytes(getattr(e, "bytes_read", b"")))
                raise
            else:
                raw_traffic_logger.debug("ASCII Receive: %s", _format_bytes(response_adu))

            # 5. Validate LRC and parse
            raw = parse_ascii_frame(response_adu)
            if raw[0] != unit_id:
                raise InvalidResponseError(
                    f"Slave address mismatch: expected {unit_id}, received {raw[0]}",
                    bytes_read=response_adu,
                )

            response_pdu = raw[1:-1]
            response_function_code = response_pdu[0]

            # 6. Exception response
            if response_function_code & 0x80:
                function_code = response_function_code & 0x7F
                exception_code = response_pdu[1] if len(response_pdu) > 1 else 0
                error_class = error_code_to_exception_map.get(exception_code, ModbusResponseError)
                raise error_class(exception_code, function_code)

            if response_function_code != pdu.function_code:
                raise InvalidResponseError(
                    f"Function code mismatch: expected {pdu.function_code}, received {response_function_code}",
                    bytes_read=response_adu,
                )

            self._last_frame_end = time.monotonic()
            return pdu.decode_response(response_pdu)

    async def _receive_response(self) -> bytes:
        """Receive complete ASCII response frame."""
        if not self._reader:
            raise ModbusConnectionError("Serial connection not established.")

        # Read until ':' (start of frame)
        while True:
            c = await asyncio.wait_for(self._reader.read(1), timeout=self.timeout)
            if not c:
                raise ModbusConnectionError("Serial port closed unexpectedly during response read.")
            if c == ASCII_FRAME_START:
                break

        # Read until '\r\n'
        frame = bytearray(b':')
        while True:
            c = await asyncio.wait_for(self._reader.read(1), timeout=self.timeout)
            if not c:
                raise ModbusConnectionError("Serial port closed unexpectedly during response read.")
            frame += c
            if frame.endswith(ASCII_FRAME_END):
                break
            # protect against garbage/flood
            if len(frame) > MAX_ASCII_FRAME_SIZE:
                raise ASCIIFrameError("ASCII frame too large", bytes_read=frame)

        self._last_frame_end = time.monotonic()
        return bytes(frame)