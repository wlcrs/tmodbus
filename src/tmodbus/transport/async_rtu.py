"""Async RTU Transport Layer Implementation.

Modbus RTU is a transmission mode defined in Modbus over Serial Line.

The messages are framed (separated) by idle (silent) periods on the line:
- each frame must be separated by the transmission time for 3.5 characters
- two consecutive characters within the same frame should not be separated
  by more than 1.5 times the transmission time of a single character.

In the case of an 19200 bits/second transmission speed, this means that:
- each frame should be separated by 2.005ms of silence
- characters must not be more than 0.859ms apart.

The detection of distinct frames by looking at these silent periods
proves to be neigh impossible when using serial-to-USB adapters.
For example: a popular FTDI chipset has a default latency timer value of
16ms. When the USB bus of the host system is under heavy usage, extra
latency may be introduced, making the detection prone to errors.

Because of this, we don't try to detect the separation between frames by
looking at the silence periods on the line, but instead calculate the
expected length of each message by looking at it's contents.
In practice, it suffices to have access to the first few bytes of each message
to determine the function code, sub-function code (if applicable) and data length
(if applicable).

Custom PDU classes must therefore implement the function `get_expected_data_length`
which returns how many bytes the data-part of the frame is expected to be.

For PDU's with a fixed length, this function can return a fixed number.
For PDU's with a variable length, the data part typically begins with a field indicating
the total length of the data in the PDU.

The default implementation of this function looks to the class variable `rtu_response_data_length`:
if this variable contains a number, this is returned as the data length. If this variable is set
to None, we assume that the data length is passed in the first byte of the data-part of the frame.

If this does not suit your needs (for example: in the case of sub-functions), then you need to
override this method with your own function.

Sources:
- https://github.com/pymodbus-dev/pymodbus/pull/880
"""

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, NotRequired, TypedDict, TypeVar, Unpack

if TYPE_CHECKING:
    from serialx import Parity, StopBits

from tmodbus.const import BROADCAST_UNIT_ID, EXCEPTION_RESPONSE_BIT, FUNCTION_CODE_MASK
from tmodbus.exceptions import (
    CRCError,
    FunctionCodeError,
    ModbusConnectionError,
    RTUFrameError,
    UnknownModbusResponseError,
    error_code_to_exception_map,
)
from tmodbus.pdu import BaseClientPDU, get_pdu_class, get_subfunction_pdu_class, is_function_code_for_subfunction_pdu
from tmodbus.utils.crc import calculate_crc16, validate_crc16
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .async_base import AsyncBaseTransport

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "RTU")
RT = TypeVar("RT")


DEFAULT_TIMEOUT = 10.0  # Default timeout in seconds for async operations


class SerialXOptions(TypedDict):
    """Options for the SerialX connection."""

    baudrate: int
    parity: NotRequired["Parity"]
    stopbits: NotRequired["StopBits"]
    bytesize: NotRequired[int]  # data bits per character: 7 for ASCII, 8 for RTU
    # Honoured by the URL-based transports (socket://, tcp://, rfc2217://,
    # esphome://), which bound establishing the connection by it.
    connect_timeout: NotRequired[float]
    xonxoff: NotRequired[bool]
    rtscts: NotRequired[bool]
    exclusive: NotRequired[bool]


MAX_RTU_FRAME_SIZE = 256  # Maximum RTU frame size in bytes

MIN_RTU_RESPONSE_LENGTH = 4  # a minimal response is: address + function code + CRC

BITS_PER_CHAR = 11  # start + 8 data + parity/stop


def compute_interframe_delay(one_char_send_duration: float) -> float:
    """Compute the Modbus RTU 3.5 character times (inter-frame delay) in seconds.

    For baudrate >= 19200, use 1.75ms.
    For baudrate < 19200, use 3.5 * (11 bits / baudrate).
    """
    interframe_delay = 3.5 * one_char_send_duration

    return max(interframe_delay, 0.00175)  # Ensure at least 1.75 ms for faster baud rates


def compute_max_continuous_transmission_delay(one_char_send_duration: float) -> float:
    """Compute the Modbus RTU continuous transmission delay in seconds.

    Once a message starts, all characters within that message must be transmitted continuously.
    The Modbus standard specifies that a silent interval of more than 1.5 character times
    between any two characters within a single frame will cause the receiving device to consider
    the message incomplete and discard it.
    """
    return 1.5 * one_char_send_duration


class AsyncRtuTransport(AsyncBaseTransport):
    """Async Modbus Serial Transport Layer Implementation.

    Handles async Modbus Serial communication based on asyncio, including:
    - Async Serial port connection management
    - RTU frame construction and parsing
    - CRC validation
    - Async error handling and timeout management
    """

    _transport: asyncio.Transport | None = None
    _protocol: "ModbusRtuProtocol | None" = None

    def __init__(
        self,
        port: str,
        *,
        timeout: float | None = None,
        on_connection_lost: Callable[[Exception | None], None] | None = None,
        **serialx_options: Unpack[SerialXOptions],
    ) -> None:
        """Initialize async Serial transport layer.

        Args:
            port: Target serial port (e.g., '/dev/ttyUSB0')
            timeout: Timeout in seconds, default 10.0 seconds
            on_connection_lost: Optional callback invoked the moment the connection is lost.
                                Receives the causing exception, or None on a clean close.
            serialx_options: Additional SerialX options like baudrate, parity, stopbits, etc.

        Raises:
            ValueError: When parameters are invalid
            TypeError: When parameter types are incorrect

        """
        self.port = port

        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        self.timeout = timeout

        self.on_connection_lost = on_connection_lost

        self.serialx_options = serialx_options

        self._baudrate = serialx_options.get("baudrate", 9600)

        one_char_send_duration = BITS_PER_CHAR / self._baudrate
        self._interframe_delay = compute_interframe_delay(one_char_send_duration)

    async def open(self) -> None:
        """Establish Serial connection."""
        try:
            import serialx  # noqa: PLC0415
        except ImportError as e:  # pragma: no cover
            msg = (
                "The 'serialx' package is required for AsyncRtuTransport."
                " Install with 'pip install tmodbus[async-serial]'"
            )
            raise ImportError(msg) from e

        loop = asyncio.get_running_loop()
        if self.is_open():
            logger.debug("Serial connection already open: %s", self.port)
            return

        try:
            # Use serialx to create a serial connection with Protocol
            transport, protocol = await asyncio.wait_for(
                serialx.create_serial_connection(
                    loop,
                    lambda: ModbusRtuProtocol(
                        on_connection_lost=self._on_connection_lost,
                        timeout=self.timeout,
                        interframe_delay=self._interframe_delay,
                    ),
                    url=self.port,
                    **self.serialx_options,
                ),
                timeout=self.timeout,
            )

            assert isinstance(transport, asyncio.WriteTransport)
            assert isinstance(protocol, ModbusRtuProtocol)
            self._transport = transport
            self._protocol = protocol

            logger.info("Async serial connection established to '%s'", self.port)

            # serialx can be slow to call connection_made, we explicitly wait for it here
            assert self._protocol
            await asyncio.wait_for(
                self._protocol.connection_made_event.wait(),
                timeout=self.timeout,
            )

        except TimeoutError:
            logger.warning("Async serial connection timeout: %s", self.port, exc_info=True)
            self._abort_failed_open()
            raise
        except Exception as e:
            logger.exception("Async serial connection error: %s", self.port)
            self._abort_failed_open()
            raise ModbusConnectionError from e

    def _abort_failed_open(self) -> None:
        """Close and clear a partially opened transport after a failed open."""
        if self._transport is not None:
            self._transport.close()
        self._transport = None
        self._protocol = None

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

        self._notify_connection_lost(exc)

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


@dataclass(frozen=True)
class _ModbusRtuMessage:
    """Dataclass representing a Modbus RTU message with address, PDU, and CRC."""

    unit_id: int
    pdu_bytes: bytes
    crc: bytes

    @property
    def bytes(self) -> bytes:
        """Get full message bytes including address, PDU, and CRC."""
        return bytes([self.unit_id]) + self.pdu_bytes + self.crc


@dataclass
class _PendingRequest:
    """Dataclass representing an in-flight pending request."""

    unit_id: int
    future: asyncio.Future[_ModbusRtuMessage]
    pdu: BaseClientPDU[Any] | None = None


class ModbusRtuProtocol(asyncio.Protocol):
    """Asyncio Protocol implementation for Modbus RTU with frame detection."""

    transport: "asyncio.WriteTransport | None" = None

    on_connection_lost: Callable[[Exception | None], None]
    timeout: float
    interframe_delay: float

    _lock: asyncio.Lock
    _buffer: bytearray
    _last_frame_ended_at: float
    _pending_request: _PendingRequest | None
    _timed_out_requests: dict[int, BaseClientPDU[Any]]

    def __init__(
        self,
        *,
        on_connection_lost: Callable[[Exception | None], None],
        timeout: float = 10.0,
        interframe_delay: float = 0.00175,
    ) -> None:
        """Initialize Modbus RTU Protocol."""
        super().__init__()

        self.on_connection_lost = on_connection_lost
        self.timeout = timeout
        self.interframe_delay = interframe_delay

        self._lock = asyncio.Lock()
        self._buffer = bytearray()
        self._last_frame_ended_at = 0.0
        self._pending_request = None
        self._timed_out_requests = {}

        self.connection_made_event = asyncio.Event()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle connection made event."""
        if not isinstance(transport, asyncio.WriteTransport):
            msg = "Expected a WriteTransport"
            raise TypeError(msg)

        self.transport = transport
        logger.info("Modbus RTU protocol connection established.")
        self.connection_made_event.set()

    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        """Async send PDU and receive response.

        Implements complete RTU protocol communication flow:
        1. Acquire bus lock (ensuring only one active transaction on the wire)
        2. Build ADU (Address + PDU + CRC)
        3. Wait for inter-frame delay
        4. Async send request
        5. Async receive response
        6. Validate CRC, address, and function code
        7. Return decoded response PDU
        """
        async with self._lock:
            broadcast_response: RT | None = None
            if unit_id == BROADCAST_UNIT_ID:
                broadcast_response = pdu.get_broadcast_response()

            if self.transport is None or self.transport.is_closing():
                msg = "Not connected."
                raise ModbusConnectionError(msg)

            # Build request frame
            request_pdu_bytes = pdu.encode_request()
            frame_prefix = bytes([unit_id]) + request_pdu_bytes
            crc = calculate_crc16(frame_prefix)
            request_adu = frame_prefix + crc

            # Wait for inter-frame delay
            time_since_last_frame = time.monotonic() - self._last_frame_ended_at
            if time_since_last_frame < self.interframe_delay:
                to_wait = self.interframe_delay - time_since_last_frame
                await asyncio.sleep(to_wait)

            # Async send request
            if broadcast_response is not None:
                # We're broadcasting an action, so just send it and return immediately
                self.transport.write(request_adu)
                log_raw_traffic("sent", request_adu)
                self._last_frame_ended_at = time.monotonic()
                return broadcast_response

            read_future: asyncio.Future[_ModbusRtuMessage] = asyncio.get_running_loop().create_future()
            self._pending_request = _PendingRequest(unit_id=unit_id, future=read_future, pdu=pdu)

            self.transport.write(request_adu)
            log_raw_traffic("sent", request_adu)
            self._last_frame_ended_at = time.monotonic()

            # Async wait for response or timeout
            try:
                response = await asyncio.wait_for(read_future, timeout=self.timeout)
            except TimeoutError as e:
                # Save PDU for timed-out request so any delayed response can be framed and discarded cleanly
                self._timed_out_requests[unit_id] = pdu
                msg = f"Response timeout after {self.timeout} seconds"
                raise TimeoutError(msg) from e
            finally:
                self._pending_request = None

            # Check if it's an exception response
            if len(response.pdu_bytes) > 0 and response.pdu_bytes[0] & EXCEPTION_RESPONSE_BIT:  # Exception response
                function_code = response.pdu_bytes[0] & FUNCTION_CODE_MASK  # Remove exception flag bit
                exception_code = response.pdu_bytes[1] if len(response.pdu_bytes) > 1 else 0

                if exception_code in error_code_to_exception_map:
                    raise error_code_to_exception_map[exception_code](function_code)
                raise UnknownModbusResponseError(exception_code, function_code)

            # Validate function code
            response_function_code = response.pdu_bytes[0]
            if response_function_code != pdu.function_code:
                msg = f"Function code mismatch: expected {pdu.function_code}, received {response_function_code}"
                raise FunctionCodeError(msg, response_bytes=response.bytes)

            # Return decoded response
            return pdu.decode_response(response.pdu_bytes)

    def _discard_garbage_data(self) -> None:
        """Discard garbage data from the buffer."""
        expected_unit_ids: set[int] = set(self._timed_out_requests.keys())
        if self._pending_request is not None and not self._pending_request.future.done():
            expected_unit_ids.add(self._pending_request.unit_id)

        if not expected_unit_ids:
            # No pending requests at all - discard everything
            logger.warning(
                "Received data with no pending requests. Discarding %d bytes: %s",
                len(self._buffer),
                self._buffer.hex(" ").upper(),
            )
            self._buffer.clear()
            return

        # Search for the first byte matching an expected unit_id
        discard_count = len(self._buffer)
        for i, byte in enumerate(self._buffer):
            if byte in expected_unit_ids:
                discard_count = i
                break

        discarded = bytes(self._buffer[:discard_count])
        logger.warning(
            "Discarding %d byte(s): %s",
            discard_count,
            discarded.hex(" ").upper(),
        )
        del self._buffer[:discard_count]

    def _resync_discard_length(self) -> int:
        """Get the number of leading bytes to discard to resynchronize after a bad frame.

        Skips ahead to the next byte matching an expected unit id, so a garbage burst is
        dropped in one slice instead of one byte per pass through the receive loop.
        """
        expected_unit_ids: set[int] = set(self._timed_out_requests.keys())
        if self._pending_request is not None and not self._pending_request.future.done():
            expected_unit_ids.add(self._pending_request.unit_id)

        for i in range(1, len(self._buffer)):
            if self._buffer[i] in expected_unit_ids:
                return i
        return 1  # no plausible frame start ahead; drop only the leading byte

    def _determine_expected_frame_length(self, pending_pdu: BaseClientPDU[Any] | None = None) -> int | None:
        """Determine expected frame length based on current buffer contents.

        Returns:
            Expected total frame length in bytes, or None if it cannot be determined yet.

        Raises:
            RTUFrameError: If the frame length is invalid.
            FunctionCodeError: If the function code does not match the pending request.

        """
        if len(self._buffer) < 2:
            return None  # Need at least address + function code
        function_code = self._buffer[1]

        if function_code & EXCEPTION_RESPONSE_BIT:  # Exception response
            expected_total_frame_length = 5  # address + exception FC + exception code + CRC
        else:
            if pending_pdu is not None and function_code != pending_pdu.function_code:
                msg = (
                    f"Function code mismatch: expected {pending_pdu.function_code:#04x}, received {function_code:#04x}"
                )
                raise FunctionCodeError(msg, response_bytes=bytes(self._buffer))

            # check if we can already determine the expected length with the available data
            try:
                if not is_function_code_for_subfunction_pdu(function_code):
                    pdu_class = get_pdu_class(function_code)
                else:
                    # It's a sub-function PDU, we need at least 6 bytes to determine the length
                    # 6 = address + function code + sub-function code + at least 1 byte of data + CRC
                    if len(self._buffer) < 6:
                        return None  # Wait for more data
                    sub_function_code = self._buffer[2]
                    pdu_class = get_subfunction_pdu_class(function_code, sub_function_code)
            except ValueError as e:
                if pending_pdu is not None:
                    pdu_class = type(pending_pdu)
                else:
                    # Unknown or unsupported (sub-)function code, for example a bit flip on the
                    # line. We cannot determine where the frame ends, so fail the pending request
                    # with a frame error rather than letting the exception crash the protocol.
                    msg = f"Cannot frame response with unsupported function code {function_code:#04x}"
                    raise RTUFrameError(msg, response_bytes=bytes(self._buffer)) from e

            # memoryview avoids an intermediate bytearray copy on every incoming chunk
            expected_response_data_length = pdu_class.get_expected_response_data_length(
                bytes(memoryview(self._buffer)[2:])
            )

            if expected_response_data_length is None:
                # the PDU class reported that it cannot yet determine the length of this response
                return None

            expected_total_frame_length = (
                1  # Slave address
                + 1  # Function code
                + expected_response_data_length
                + 2  # CRC
            )

        #  Validate frame size
        if not (0 <= expected_total_frame_length <= MAX_RTU_FRAME_SIZE):
            # there is a bug in the PDU class implementation: it returns an incorrect length
            logger.error(
                "The PDU class returned an invalid expected length. "
                "This is a bug in the PDU class. Discarding buffer: %s",
                bytes(self._buffer).hex(" ").upper(),
            )
            response_bytes = bytes(self._buffer)
            self._buffer.clear()
            msg = (
                f"Expected frame length {expected_total_frame_length} is invalid: "
                f"must be between 0 and {MAX_RTU_FRAME_SIZE}"
            )
            raise RTUFrameError(msg, response_bytes=response_bytes)

        return expected_total_frame_length

    def _try_drain_timed_out_response(self, unit_id: int, timed_out_pdu: BaseClientPDU[Any]) -> bool:
        """Attempt to frame and discard a delayed response for a timed-out request.

        Returns:
            True if waiting for more data, False if frame was processed or skipped.

        """
        try:
            expected_total_frame_length = self._determine_expected_frame_length(timed_out_pdu)
        except (RTUFrameError, FunctionCodeError):
            self._timed_out_requests.pop(unit_id, None)
            del self._buffer[: self._resync_discard_length()]
            return False

        if expected_total_frame_length is None or len(self._buffer) < expected_total_frame_length:
            return True  # Wait for full delayed frame

        candidate_frame = bytes(memoryview(self._buffer)[:expected_total_frame_length])
        if validate_crc16(candidate_frame):
            del self._buffer[:expected_total_frame_length]
            self._timed_out_requests.pop(unit_id, None)
            logger.info(
                "Cleanly framed and discarded delayed response for timed-out request on unit %d: %s",
                unit_id,
                candidate_frame.hex(" ").upper(),
            )
        else:
            del self._buffer[: self._resync_discard_length()]
        return False

    def _validate_and_deliver_frame(
        self,
        unit_id: int,
        expected_length: int,
        pending_future: asyncio.Future[_ModbusRtuMessage],
    ) -> Exception | None:
        """Extract, validate, and deliver a complete candidate frame."""
        candidate_frame = bytes(memoryview(self._buffer)[:expected_length])
        if validate_crc16(candidate_frame):
            del self._buffer[:expected_length]
            pdu_bytes = candidate_frame[1:-2]  # Remove address and CRC
            crc = candidate_frame[-2:]
            self._timed_out_requests.pop(unit_id, None)
            pending_future.set_result(
                _ModbusRtuMessage(
                    unit_id=unit_id,
                    pdu_bytes=pdu_bytes,
                    crc=crc,
                )
            )
            return None

        discard_length = self._resync_discard_length()
        logger.warning(
            "CRC validation failed for candidate frame (%d bytes: %s). Discarding %d byte(s) to resynchronize.",
            len(candidate_frame),
            candidate_frame.hex(" ").upper(),
            discard_length,
        )
        del self._buffer[:discard_length]
        return CRCError(response_bytes=candidate_frame)

    def _try_drain_delayed_matching_response(
        self,
        unit_id: int,
        pending_pdu: BaseClientPDU[Any] | None,
    ) -> bool | None:
        """Check and attempt to drain a delayed response matching a timed-out request.

        Returns:
            True if waiting for more data, False if drained or skipped, or None if no match.

        """
        timed_out_pdu = self._timed_out_requests.get(unit_id)
        if timed_out_pdu is not None and len(self._buffer) >= 2:
            raw_function_code = self._buffer[1]
            base_function_code = raw_function_code & FUNCTION_CODE_MASK
            if (
                pending_pdu is not None
                and base_function_code != (pending_pdu.function_code & FUNCTION_CODE_MASK)
                and base_function_code == (timed_out_pdu.function_code & FUNCTION_CODE_MASK)
            ):
                return self._try_drain_timed_out_response(unit_id, timed_out_pdu)
        return None

    def _handle_inactive_unit_data(self, unit_id: int) -> bool:
        """Handle data for a unit ID with no active request.

        Returns:
            True if caller should return immediately (waiting for more data), False to continue.

        """
        timed_out_pdu = self._timed_out_requests.get(unit_id)
        if timed_out_pdu is None and self._pending_request is not None and self._pending_request.unit_id == unit_id:
            timed_out_pdu = self._pending_request.pdu

        if timed_out_pdu is not None:
            return self._try_drain_timed_out_response(unit_id, timed_out_pdu)

        # No pending or timed-out request for this unit_id - this is garbage data
        self._discard_garbage_data()
        return False

    def data_received(self, data: bytes) -> None:
        """Handle data received event.

        Limitations of RTU delayed-response detection:
            Modbus RTU responses do not contain Transaction IDs (TIDs) or sequence numbers.
            - If a delayed response arrives with a DIFFERENT Function Code than the active
              request, tmodbus accurately attributes it to the timed-out request and drains it
              without disrupting the active request.
            - If a delayed response arrives with the SAME Function Code and byte structure as
              the active request, it is mathematically indistinguishable on the wire from the
              genuine response to the active request. In that case, it will be accepted as the
              response to the active request and the timed-out tracking will be cleared.
        """
        self._buffer.extend(data)
        log_raw_traffic("recv", data)

        last_error: Exception | None = None

        # Try to process complete frames
        while len(self._buffer) >= MIN_RTU_RESPONSE_LENGTH:
            # Step 1: Check if first byte is a unit_id with an active or timed-out request
            unit_id = self._buffer[0]

            # Step 2: Check if this unit_id has an active pending request
            pending = self._pending_request
            has_active_request = pending is not None and pending.unit_id == unit_id and not pending.future.done()

            if not has_active_request:
                if self._handle_inactive_unit_data(unit_id):
                    return
                continue

            # Step 3: We have an active pending request. Check for matching delayed response.
            assert pending is not None
            delayed_drain_result = self._try_drain_delayed_matching_response(unit_id, pending.pdu)
            if delayed_drain_result is True:
                return
            if delayed_drain_result is False:
                continue

            # Step 4: Determine expected frame length for active request
            try:
                expected_total_frame_length = self._determine_expected_frame_length(pending.pdu)
            except (RTUFrameError, FunctionCodeError) as e:
                logger.warning(
                    "Framing error for unit %d: %s. Discarding leading byte %s",
                    unit_id,
                    e,
                    self._buffer[0:1].hex(" ").upper() if self._buffer else "",
                )
                last_error = e
                if self._buffer:
                    del self._buffer[0]
                continue

            if expected_total_frame_length is None or len(self._buffer) < expected_total_frame_length:
                return  # Wait for more data

            # Step 5: Extract, validate CRC, and deliver frame
            last_error = self._validate_and_deliver_frame(unit_id, expected_total_frame_length, pending.future)

        if (
            last_error is not None
            and self._pending_request is not None
            and self._pending_request.unit_id not in self._buffer
        ):
            self._pending_request.future.set_exception(last_error)

    def connection_lost(self, exc: Exception | None) -> None:
        """Handle connection lost event."""
        if self._pending_request is not None and not self._pending_request.future.done():
            self._pending_request.future.set_exception(
                ModbusConnectionError("Connection lost before response was received.")
            )

        self._pending_request = None
        self._timed_out_requests.clear()
        self.on_connection_lost(exc)
