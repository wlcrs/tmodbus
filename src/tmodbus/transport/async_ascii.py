"""Async ASCII Transport Layer Implementation.

Implements async Modbus ASCII protocol transport based on asyncio, including LRC processing.
"""

import asyncio
import logging
import time
from functools import partial
from typing import NotRequired, TypedDict, TypeVar, Unpack

try:
    import serial_asyncio_fast
except ImportError as e:  # pragma: no cover
    msg = (
        "The 'serial_asyncio_fast' package is required for AsyncRtuTransport."
        " Install with 'pip install tmodbus[async-rtu]'"
    )
    raise ImportError(msg) from e

from tmodbus.exceptions import (
    ASCIIFrameError,
    InvalidResponseError,
    LRCError,
    ModbusConnectionError,
    UnknownModbusResponseError,
    error_code_to_exception_map,
)
from tmodbus.pdu import BaseClientPDU
from tmodbus.utils.lrc import calculate_lrc, validate_lrc
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .async_base import AsyncBaseTransport

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "ASCII")
RT = TypeVar("RT")

DEFAULT_TIMEOUT = 10.0  # Default timeout in seconds for async operations


class PySerialOptions(TypedDict):
    """Options for the PySerial connection."""

    baudrate: int
    bytesize: NotRequired[int]
    parity: NotRequired[str]
    stopbits: NotRequired[float]
    timeout: NotRequired[float | None]
    xonxoff: NotRequired[bool]
    rtscts: NotRequired[bool]
    write_timeout: NotRequired[float | None]
    dsrdtr: NotRequired[bool]
    inter_byte_timeout: NotRequired[float | None]


ASCII_FRAME_START = b":"
ASCII_FRAME_END = b"\r\n"
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
    lrc = calculate_lrc(message)
    # Add LRC as an extra byte to the message before encoding
    message_with_lrc = message + bytes([lrc])
    return ASCII_FRAME_START + ascii_encode(message_with_lrc) + ASCII_FRAME_END


def parse_ascii_frame(frame: bytes) -> bytes:
    """Parse Modbus ASCII frame (strip start/end, decode hex, check LRC)."""
    if not frame.startswith(ASCII_FRAME_START) or not frame.endswith(ASCII_FRAME_END):
        msg = "Malformed ASCII frame: does not start with ':' and end with '\\r\\n'"
        raise ASCIIFrameError(msg, response_bytes=frame)
    # Remove ':' ... '\r\n'
    hex_payload = frame[1:-2]
    try:
        raw: bytes = ascii_decode(hex_payload)
    except Exception as e:
        msg = "Invalid hex in ASCII frame"
        raise ASCIIFrameError(msg, response_bytes=frame) from e
    if len(raw) < 3:
        msg = "ASCII frame too short"
        raise ASCIIFrameError(msg, response_bytes=frame)
    message, lrc = raw[:-1], raw[-1]
    if not validate_lrc(message, lrc):
        raise LRCError(response_bytes=frame)
    return raw  # address + pdu + lrc


class AsyncAsciiTransport(AsyncBaseTransport):
    """Async Modbus ASCII Transport Layer Implementation.

    Handles async Modbus Serial communication using the ASCII framing, LRC checking, and timeouts.
    """

    _reader: asyncio.StreamReader | None = None
    _writer: asyncio.StreamWriter | None = None
    _last_frame_ended_at: float = 0.0
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
                    serial_asyncio_fast.open_serial_connection(
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
            except Exception as e:  # noqa: BLE001
                logger.debug("Error during async connection close (ignorable): %s", e)
            finally:
                self._reader = None
                self._writer = None

    def is_open(self) -> bool:
        """Check Serial connection status."""
        if self._writer is None or self._reader is None:
            return False
        return not self._writer.is_closing()

    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        r"""Async send PDU and receive response (ASCII mode).

        1. Build ASCII frame (':' + hex + LRC + '\r\n')
        2. Wait for end-of-frame gap (min 1 char time)
        3. Send request
        4. Receive response
        5. Validate LRC/format
        6. Validate address
        7. Check for error response
        8. Mark end of frame
        """
        async with self._communication_lock:
            if not self.is_open():
                msg = "Not connected."
                raise ModbusConnectionError(msg)

            # 1. Build request frame
            request_pdu_bytes = pdu.encode_request()
            request_adu = build_ascii_frame(unit_id, request_pdu_bytes)

            log_raw_traffic("sent", request_adu)

            # 2. Wait for end-of-frame gap (1 char time minimum)
            # For simplicity, use 1ms
            time_since_last_frame = time.monotonic() - self._last_frame_ended_at
            min_gap = 0.001
            if time_since_last_frame < min_gap:
                await asyncio.sleep(min_gap - time_since_last_frame)

            # 3. Send request
            if not self._writer:
                msg = "Connection not established."
                raise ModbusConnectionError(msg)
            self._writer.write(request_adu)
            await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)

            # 4. Receive response
            try:
                response_adu: bytes = await self._receive_response()
            except (ASCIIFrameError, ModbusConnectionError) as e:
                log_raw_traffic("recv", e.response_bytes, is_error=True)
                raise
            else:
                log_raw_traffic("recv", response_adu)

            # 5. Validate LRC and parse
            raw = parse_ascii_frame(response_adu)

            # 6. Validate slave address
            if raw[0] != unit_id:
                msg = f"Slave address mismatch: expected {unit_id}, received {raw[0]}"
                raise InvalidResponseError(msg, response_bytes=response_adu)

            response_pdu = raw[1:-1]
            response_function_code = response_pdu[0]

            # 7. Exception response
            if response_function_code & 0x80:
                function_code = response_function_code & 0x7F
                exception_code = response_pdu[1] if len(response_pdu) > 1 else 0

                error_class = error_code_to_exception_map.get(exception_code, UnknownModbusResponseError)
                raise error_class(exception_code, function_code)

            if response_function_code != pdu.function_code:
                msg = f"Function code mismatch: expected {pdu.function_code}, received {response_function_code}"
                raise InvalidResponseError(msg, response_bytes=response_adu)

            # 8. Mark the end of this frame
            self._last_frame_ended_at = time.monotonic()
            return pdu.decode_response(response_pdu)

    async def _receive_response(self) -> bytes:
        """Receive complete ASCII response frame."""
        if not self._reader:
            msg = "Serial connection not established."
            raise ModbusConnectionError(msg)

        try:
            # Read until ':' (start of frame)
            c = await asyncio.wait_for(self._reader.readuntil(ASCII_FRAME_START), timeout=self.timeout)
            if len(c) > 1:
                log_raw_traffic("recv", c[:-1], is_error=True)
                logger.info("Discarded %d bytes of garbage before start of frame: %s", len(c) - 1, c[:-1])

            frame = bytearray([c[-1]])

            # Read until '\r\n'
            while not frame.endswith(ASCII_FRAME_END) and not len(frame) > MAX_ASCII_FRAME_SIZE:
                frame += await asyncio.wait_for(self._reader.readline(), timeout=self.timeout)

        except asyncio.IncompleteReadError as e:
            msg = "Incomplete read while waiting for start of frame."
            raise ASCIIFrameError(msg, response_bytes=e.partial) from e
        except TimeoutError:
            raise
        except Exception as e:
            msg = "Failed to read Modbus response."
            raise ModbusConnectionError(msg) from e
        else:
            # protect against garbage/flood
            if len(frame) > MAX_ASCII_FRAME_SIZE:
                msg = "ASCII frame too large"
                raise ASCIIFrameError(msg, response_bytes=frame)

            return frame
        finally:
            self._last_frame_ended_at = time.monotonic()
