"""Async ASCII Transport Layer Implementation.

Implements async Modbus ASCII protocol transport based on asyncio, including LRC processing.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import NotRequired, TypedDict, TypeVar, Unpack

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
MIN_INTERFRAME_GAP = 0.001  # Minimum gap between frames in seconds (1ms)


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


@dataclass(frozen=True)
class _ModbusAsciiMessage:
    """Dataclass representing a Modbus ASCII message with address, PDU, and LRC."""

    unit_id: int
    pdu_bytes: bytes
    lrc: bytes

    @property
    def bytes(self) -> bytes:
        """Get full message bytes including address, PDU, and LRC."""
        return bytes([self.unit_id]) + self.pdu_bytes + self.lrc


class ModbusAsciiProtocol(asyncio.Protocol):
    """Asyncio Protocol implementation for Modbus ASCII with frame detection."""

    transport: "asyncio.WriteTransport | None" = None

    on_connection_lost: Callable[[Exception | None], None]
    timeout: float
    interframe_gap: float

    _buffer: bytearray
    _last_frame_ended_at: float
    _pending_requests: dict[int, asyncio.Future[_ModbusAsciiMessage]]

    def __init__(
        self,
        *,
        on_connection_lost: Callable[[Exception | None], None],
        timeout: float = 10.0,
        interframe_gap: float = MIN_INTERFRAME_GAP,
    ) -> None:
        """Initialize Modbus ASCII Protocol."""
        super().__init__()

        self.on_connection_lost = on_connection_lost
        self.timeout = timeout
        self.interframe_gap = interframe_gap

        self._buffer = bytearray()
        self._last_frame_ended_at = 0.0
        self._pending_requests = {}

        self.connection_made_event = asyncio.Event()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle connection made event."""
        if not isinstance(transport, asyncio.WriteTransport):
            msg = "Expected a WriteTransport"
            raise TypeError(msg)

        self.transport = transport
        logger.info("Modbus ASCII protocol connection established.")
        self.connection_made_event.set()

    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        r"""Async send PDU and receive response (ASCII mode).

        Implements complete ASCII protocol communication flow:
        1. Wait for any pending request for this unit_id to complete
        2. Build ASCII frame (':' + hex + LRC + '\r\n')
        3. Wait for inter-frame gap
        4. Async send request
        5. Async receive response
        6. Validate LRC and address
        7. Return response PDU
        """
        if self.transport is None or self.transport.is_closing():
            msg = "Not connected."
            raise ModbusConnectionError(msg)

        # 1. Wait for any existing request for this unit_id to complete
        await self._wait_on_pending_request(unit_id)

        # 2. Build request frame
        request_pdu_bytes = pdu.encode_request()
        request_adu = build_ascii_frame(unit_id, request_pdu_bytes)

        # 3. Wait for inter-frame gap
        time_since_last_frame = time.monotonic() - self._last_frame_ended_at
        if time_since_last_frame < self.interframe_gap:
            to_wait = self.interframe_gap - time_since_last_frame
            await asyncio.sleep(to_wait)

        # 4. Async send request
        read_future: asyncio.Future[_ModbusAsciiMessage] = asyncio.get_event_loop().create_future()
        self._pending_requests[unit_id] = read_future

        self.transport.write(request_adu)
        log_raw_traffic("sent", request_adu)
        # Mark the end of this frame
        self._last_frame_ended_at = time.monotonic()

        # 5. Async wait for response or timeout
        try:
            response = await asyncio.wait_for(read_future, timeout=self.timeout)
        except TimeoutError as e:
            logger.exception(
                "Response timeout for unit %d after %.2f seconds. Cancelling read future.", unit_id, self.timeout
            )
            read_future.cancel()
            msg = f"Response timeout after {self.timeout} seconds"
            raise TimeoutError(msg) from e
        finally:
            # Remove from pending requests
            self._pending_requests.pop(unit_id, None)

        # 6. Check if it's an exception response
        if len(response.pdu_bytes) > 0 and response.pdu_bytes[0] & 0x80:  # Exception response
            function_code = response.pdu_bytes[0] & 0x7F  # Remove exception flag bit
            exception_code = response.pdu_bytes[1] if len(response.pdu_bytes) > 1 else 0

            error_class = error_code_to_exception_map.get(exception_code, UnknownModbusResponseError)
            raise error_class(exception_code, function_code)

        # 7. Validate function code
        response_function_code = response.pdu_bytes[0]
        if response_function_code != pdu.function_code:
            msg = f"Function code mismatch: expected {pdu.function_code}, received {response_function_code}"
            raise InvalidResponseError(msg, response_bytes=response.bytes)

        # 8. Return decoded response
        return pdu.decode_response(response.pdu_bytes)

    async def _wait_on_pending_request(self, unit_id: int) -> None:
        """Wait for any existing pending request for the given unit_id to complete."""
        existing_future = self._pending_requests.get(unit_id)
        if existing_future is not None and not existing_future.done():
            # Wait for the previous request to complete (or fail)
            # If it fails, we continue with the new request
            try:
                await asyncio.wait_for(existing_future, timeout=self.timeout)
            except TimeoutError:
                logger.debug("Previous request for unit %d timed out, proceeding with new request", unit_id)
            except asyncio.CancelledError:
                logger.debug("Previous request for unit %d was cancelled, proceeding with new request", unit_id)
            except Exception as e:  # noqa: BLE001
                logger.debug("Previous request for unit %d failed: %s, proceeding with new request", unit_id, e)
            else:
                logger.debug("Previous request for unit %d succeeded, proceeding with new request", unit_id)

    def _discard_garbage_data(self) -> None:
        """Discard garbage data from the buffer until we find a frame start."""
        # Look for the next ASCII_FRAME_START (':')
        start_pos = self._buffer.find(ASCII_FRAME_START)

        if start_pos == -1:
            # No start marker found, discard everything
            if len(self._buffer) > 0:
                logger.warning(
                    "No frame start found. Discarding %d bytes: %s",
                    len(self._buffer),
                    self._buffer.hex(" ").upper(),
                )
                self._buffer.clear()
        elif start_pos > 0:
            # Found start marker, discard everything before it
            discarded = bytes(self._buffer[:start_pos])
            logger.warning(
                "Discarding %d byte(s) before frame start: %s",
                start_pos,
                discarded.hex(" ").upper(),
            )
            del self._buffer[:start_pos]

    def data_received(self, data: bytes) -> None:
        """Handle data received event."""
        self._buffer.extend(data)
        log_raw_traffic("recv", data)

        # Try to process complete frames
        while len(self._buffer) >= 1:
            # Look for a complete frame: ':' ... '\r\n'
            if not self._buffer.startswith(ASCII_FRAME_START):
                # Buffer doesn't start with ':', discard garbage
                self._discard_garbage_data()
                continue

            # Look for frame end
            end_pos = self._buffer.find(ASCII_FRAME_END)
            if end_pos == -1:
                # No complete frame yet
                # Check if buffer is getting too large (potential garbage/flood)
                if len(self._buffer) > MAX_ASCII_FRAME_SIZE:
                    logger.warning(
                        "Buffer exceeded max frame size. Discarding %d bytes: %s",
                        len(self._buffer),
                        self._buffer.hex(" ").upper(),
                    )
                    self._buffer.clear()
                return  # Wait for more data

            # Extract complete frame
            frame_length = end_pos + len(ASCII_FRAME_END)
            frame = bytes(self._buffer[:frame_length])
            del self._buffer[:frame_length]

            # Parse and validate the frame
            try:
                raw = parse_ascii_frame(frame)
            except (ASCIIFrameError, LRCError) as e:
                logger.warning("Invalid frame received: %s", e)
                # Continue to next frame
                continue

            # Extract unit_id from frame
            unit_id = raw[0]
            pdu_bytes = raw[1:-1]  # Remove address and LRC
            lrc = raw[-1:]

            # Check if this unit_id has a pending request
            pending_future = self._pending_requests.get(unit_id)
            if pending_future is None or pending_future.done():
                # No pending request for this unit_id
                logger.warning(
                    "Received frame for unit %d with no pending request. Discarding frame.",
                    unit_id,
                )
                continue

            # Deliver response to pending request
            pending_future.set_result(
                _ModbusAsciiMessage(
                    unit_id=unit_id,
                    pdu_bytes=pdu_bytes,
                    lrc=lrc,
                )
            )

    def connection_lost(self, exc: Exception | None) -> None:
        """Handle connection lost event."""
        # Set exception on all pending requests
        for pending_future in self._pending_requests.values():
            if not pending_future.done():
                pending_future.set_exception(ModbusConnectionError("Connection lost before response was received."))

        self._pending_requests.clear()
        self.on_connection_lost(exc)


class AsyncAsciiTransport(AsyncBaseTransport):
    """Async Modbus ASCII Transport Layer Implementation.

    Handles async Modbus Serial communication using the ASCII framing, LRC checking, and timeouts.
    """

    _transport: asyncio.Transport | None = None
    _protocol: "ModbusAsciiProtocol | None" = None

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

        timeout = pyserial_options.get("timeout")
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        self.timeout = timeout

    async def open(self) -> None:
        """Establish Serial connection."""
        try:
            import serial_asyncio_fast  # noqa: PLC0415
        except ImportError as e:  # pragma: no cover
            msg = (
                "The 'serial_asyncio_fast' package is required for AsyncAsciiTransport."
                " Install with 'pip install tmodbus[async-serial]'"
            )
            raise ImportError(msg) from e

        loop = asyncio.get_running_loop()
        if self.is_open():
            logger.debug("Serial connection already open: %s", self.port)
            return

        try:
            # Use serial_asyncio_fast to create a serial connection with Protocol
            transport, protocol = await asyncio.wait_for(
                serial_asyncio_fast.create_serial_connection(
                    loop,
                    lambda: ModbusAsciiProtocol(
                        on_connection_lost=self._on_connection_lost,
                        timeout=self.timeout,
                        interframe_gap=MIN_INTERFRAME_GAP,
                    ),
                    url=self.port,
                    **self.pyserial_options,
                ),
                timeout=self.pyserial_options.get("timeout", DEFAULT_TIMEOUT),
            )

            assert isinstance(transport, asyncio.WriteTransport)
            assert isinstance(protocol, ModbusAsciiProtocol)
            self._transport = transport
            self._protocol = protocol

            logger.info("Async Serial connection established to '%s'", self.port)

            # pyserial can be slow to call connection_made, we explicitly wait for it here
            assert self._protocol
            await asyncio.wait_for(
                self._protocol.connection_made_event.wait(),
                timeout=self.timeout,
            )

        except TimeoutError:
            logger.warning("Async Serial connection timeout: %s", self.port, exc_info=True)
            raise
        except Exception as e:
            logger.exception("Async Serial connection error: %s", self.port)
            raise ModbusConnectionError from e

    async def close(self) -> None:
        """Close Serial connection."""
        if not self._transport or self._transport.is_closing():
            logger.debug("Serial connection already closed: %s", self.port)
            return

        try:
            self._transport.close()
            logger.info("Serial connection closed: %s", self.port)
        except Exception as e:  # noqa: BLE001
            logger.debug("Error during async connection close: %s", e)

    def is_open(self) -> bool:
        """Check Serial connection status."""
        return self._transport is not None and not self._transport.is_closing()

    def _on_connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.error("Async Serial connection lost due to error: %s", exc)
        else:
            logger.info("Async Serial connection closed.")

        self._transport = None
        self._protocol = None

    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        """Async send PDU and receive response.

        Args:
            unit_id: Unit identifier (slave address)
            pdu: PDU object to send

        """
        if not self.is_open() or self._protocol is None:
            msg = "Transport is not connected."
            raise ModbusConnectionError(msg)

        return await self._protocol.send_and_receive(unit_id, pdu)
