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
from typing import NotRequired, TypedDict, TypeVar, Unpack

from tmodbus.exceptions import (
    CRCError,
    InvalidResponseError,
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
        **pyserial_options: Unpack[PySerialOptions],
    ) -> None:
        """Initialize async Serial transport layer.

        Args:
            port: Target serial port (e.g., '/dev/ttyUSB0')
            timeout: Timeout in seconds, default 10.0 seconds
            pyserial_options: Additional PySerial options like baudrate, bytesize, parity, etc.

        Raises:
            ValueError: When parameters are invalid
            TypeError: When parameter types are incorrect

        """
        self.port = port
        self.pyserial_options = pyserial_options

        timeout = pyserial_options.get("timeout")
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        self.timeout = timeout
        self._baudrate = pyserial_options.get("baudrate", 9600)

        one_char_send_duration = BITS_PER_CHAR / self._baudrate
        self._interframe_delay = compute_interframe_delay(one_char_send_duration)

    async def open(self) -> None:
        """Establish Serial connection."""
        try:
            import serial_asyncio_fast  # noqa: PLC0415
        except ImportError as e:  # pragma: no cover
            msg = (
                "The 'serial_asyncio_fast' package is required for AsyncRtuTransport."
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
                    lambda: ModbusRtuProtocol(
                        on_connection_lost=self._on_connection_lost,
                        timeout=self.timeout,
                        interframe_delay=self._interframe_delay,
                    ),
                    url=self.port,
                    **self.pyserial_options,
                ),
                timeout=self.pyserial_options.get("timeout", DEFAULT_TIMEOUT),
            )

            assert isinstance(transport, asyncio.WriteTransport)
            assert isinstance(protocol, ModbusRtuProtocol)
            self._transport = transport
            self._protocol = protocol

            logger.info("Async serial connection established to '%s'", self.port)

            # pyserial can be slow to call connection_made, we explicitly wait for it here
            assert self._protocol
            await asyncio.wait_for(
                self._protocol.connection_made_event.wait(),
                timeout=self.timeout,
            )

        except TimeoutError:
            logger.warning("Async serial connection timeout: %s", self.port, exc_info=True)
            raise
        except Exception as e:
            logger.exception("Async serial connection error: %s", self.port)
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


class ModbusRtuProtocol(asyncio.Protocol):
    """Asyncio Protocol implementation for Modbus RTU with frame detection."""

    transport: "asyncio.WriteTransport | None" = None

    on_connection_lost: Callable[[Exception | None], None]
    timeout: float
    interframe_delay: float

    _buffer: bytearray
    _last_frame_ended_at: float
    _pending_requests: dict[int, asyncio.Future[_ModbusRtuMessage]]

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
        logger.info("Modbus RTU protocol connection established.")
        self.connection_made_event.set()

    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        """Async send PDU and receive response.

        Implements complete RTU protocol communication flow:
        1. Wait for any pending request for this unit_id to complete
        2. Build ADU (Address + PDU + CRC)
        3. Wait for inter-frame delay
        4. Async send request
        5. Async receive response
        6. Validate CRC and address
        7. Return response PDU
        """
        if self.transport is None or self.transport.is_closing():
            msg = "Not connected."
            raise ModbusConnectionError(msg)

        # 1. Wait for any existing request for this unit_id to complete
        await self._wait_on_pending_request(unit_id)

        # 2. Build request frame
        request_pdu_bytes = pdu.encode_request()
        frame_prefix = bytes([unit_id]) + request_pdu_bytes
        crc = calculate_crc16(frame_prefix)
        request_adu = frame_prefix + crc

        # 3. Wait for inter-frame delay
        time_since_last_frame = time.monotonic() - self._last_frame_ended_at
        if time_since_last_frame < self.interframe_delay:
            to_wait = self.interframe_delay - time_since_last_frame
            await asyncio.sleep(to_wait)

        # 4. Async send request
        read_future: asyncio.Future[_ModbusRtuMessage] = asyncio.get_event_loop().create_future()
        self._pending_requests[unit_id] = read_future

        self.transport.write(request_adu)
        log_raw_traffic("sent", request_adu)
        # Mark the end of this frame
        self._last_frame_ended_at = time.monotonic()

        # 5. Async wait for response or timeout
        try:
            response = await asyncio.wait_for(read_future, timeout=self.timeout)
        except TimeoutError as e:
            msg = f"Response timeout after {self.timeout} seconds"
            raise TimeoutError(msg) from e
        finally:
            # Remove from pending requests
            self._pending_requests.pop(unit_id, None)

        # 7. Check if it's an exception response
        if len(response.pdu_bytes) > 0 and response.pdu_bytes[0] & 0x80:  # Exception response
            function_code = response.pdu_bytes[0] & 0x7F  # Remove exception flag bit
            exception_code = response.pdu_bytes[1] if len(response.pdu_bytes) > 1 else 0

            error_class = error_code_to_exception_map.get(exception_code, UnknownModbusResponseError)
            raise error_class(exception_code, function_code)

        # 8. Validate function code
        response_function_code = response.pdu_bytes[0]
        if response_function_code != pdu.function_code:
            msg = f"Function code mismatch: expected {pdu.function_code}, received {response_function_code}"
            raise InvalidResponseError(msg, response_bytes=response.bytes)

        # 9. Return decoded response
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
        """Discard garbage data from the buffer."""
        # Find the first byte that matches a unit_id with an outstanding request
        expected_unit_ids = {uid for uid, fut in self._pending_requests.items() if not fut.done()}

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
        discard_count = 0
        for i in range(len(self._buffer)):
            if self._buffer[i] in expected_unit_ids:
                # Found a potential match
                discard_count = i
                break
        else:
            # No matching unit_id found in buffer
            discard_count = len(self._buffer)

        if discard_count > 0:
            discarded = bytes(self._buffer[:discard_count])
            logger.warning(
                "Discarding %d byte(s): %s",
                discard_count,
                discarded.hex(" ").upper(),
            )
            del self._buffer[:discard_count]
        else:  # pragma: no cover
            # This shouldn't happen, but just in case
            logger.warning(
                "Unexpected state in garbage handling. Discarding first byte: %s",
                self._buffer[0:1].hex(" ").upper(),
            )
            del self._buffer[0]

    def _determine_expected_frame_length(self) -> int | None:
        """Determine expected frame length based on current buffer contents.

        Returns:
            Expected total frame length in bytes, or None if it cannot be determined yet.

        Raises:
            RTUFrameError: If the frame length is invalid.

        """
        if len(self._buffer) < 2:
            return None  # Need at least address + function code
        function_code = self._buffer[1]

        if function_code & 0x80:  # Exception response
            expected_total_frame_length = 5  # address + exception FC + exception code + CRC
        else:
            # check if we can already determine the expected length with the available data
            if not is_function_code_for_subfunction_pdu(function_code):
                pdu_class = get_pdu_class(function_code)
            else:
                # It's a sub-function PDU, we need at least 6 bytes to determine the length
                # 6 = address + function code + sub-function code + at least 1 byte of data + CRC
                if len(self._buffer) < 6:
                    return None  # Wait for more data
                sub_function_code = self._buffer[2]
                pdu_class = get_subfunction_pdu_class(function_code, sub_function_code)

            expected_response_data_length = pdu_class.get_expected_response_data_length(self._buffer[2:])

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
            self._buffer.clear()
            msg = (
                f"Expected frame length {expected_total_frame_length} is invalid: "
                f"must be between 0 and {MAX_RTU_FRAME_SIZE}"
            )
            raise RTUFrameError(msg, response_bytes=bytes(self._buffer))

        return expected_total_frame_length

    def data_received(self, data: bytes) -> None:
        """Handle data received event."""
        self._buffer.extend(data)
        log_raw_traffic("recv", data)

        # Try to process complete frames
        while len(self._buffer) >= MIN_RTU_RESPONSE_LENGTH:
            # Step 1: Check if first byte is a unit_id with a pending request
            unit_id = self._buffer[0]

            # Step 2: Check if this unit_id has a pending request
            pending_future = self._pending_requests.get(unit_id)
            if pending_future is None or pending_future.done():
                # No pending request for this unit_id - this is garbage data
                self._discard_garbage_data()
                continue

            # Step 3: Determine expected frame length
            try:
                expected_total_frame_length = self._determine_expected_frame_length()
            except RTUFrameError as e:
                pending_future.set_exception(e)
                return

            if expected_total_frame_length is None or len(self._buffer) < expected_total_frame_length:
                return  # Wait for more data

            # Step 6: Extract complete frame
            frame = bytes(self._buffer[:expected_total_frame_length])
            del self._buffer[:expected_total_frame_length]

            # Step 7: Deliver response to pending request
            pdu_bytes = frame[1:-2]  # Remove address and CRC
            crc = frame[-2:]

            # 6. Validate CRC
            if validate_crc16(frame):
                pending_future.set_result(
                    _ModbusRtuMessage(
                        unit_id=unit_id,
                        pdu_bytes=pdu_bytes,
                        crc=crc,
                    )
                )
            else:
                pending_future.set_exception(CRCError(response_bytes=frame))

    def connection_lost(self, exc: Exception | None) -> None:
        """Handle connection lost event."""
        # Set exception on all pending requests
        for pending_future in self._pending_requests.values():
            if not pending_future.done():
                pending_future.set_exception(ModbusConnectionError("Connection lost before response was received."))

        self._pending_requests.clear()
        self.on_connection_lost(exc)
