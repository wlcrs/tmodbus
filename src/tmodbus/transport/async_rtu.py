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
from functools import partial
from typing import NotRequired, TypedDict, TypeVar, Unpack

try:
    import serial_asyncio_fast
except ImportError as e:
    msg = (
        "The 'serial_asyncio_fast' package is required for AsyncRtuTransport."
        " Install with 'pip install tmodbus[async-rtu]'"
    )
    raise ImportError(msg) from e

from tmodbus.exceptions import (
    CRCError,
    InvalidResponseError,
    ModbusConnectionError,
    ModbusResponseError,
    RTUFrameError,
    error_code_to_exception_map,
)
from tmodbus.pdu import BasePDU, get_pdu_class
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
    - MBAP header construction and parsing
    - Transaction identifier management
    - Async error handling and timeout management
    """

    _reader: asyncio.StreamReader | None = None
    _writer: asyncio.StreamWriter | None = None
    _last_frame_ended_at: float = 0.0
    _communication_lock: asyncio.Lock  # Prevents concurrent access to the transport layer

    pyserial_options: PySerialOptions

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
        self.timeout = pyserial_options.get("timeout", DEFAULT_TIMEOUT)
        self._baudrate = pyserial_options.get("baudrate", 9600)

        one_char_send_duration = BITS_PER_CHAR / self._baudrate
        self._interframe_delay = compute_interframe_delay(one_char_send_duration)
        self._max_continuous_transmission_delay = compute_max_continuous_transmission_delay(one_char_send_duration)

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
        """Close TCP connection."""
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

    async def send_and_receive(self, unit_id: int, pdu: BasePDU[RT]) -> RT:
        """Async send PDU and receive response.

        Implements complete RTU protocol communication flow:
        1. Build ADU (Address + PDU + CRC)
        2. Wait for inter-frame delay
        3. Send request
        4. Receive response
        5. Validate CRC
        6. Return response PDU
        """
        async with self._communication_lock:
            if not self.is_open():
                msg = "Not connected."
                raise ModbusConnectionError(msg)

            # 1. Build request frame
            request_pdu_bytes = pdu.encode_request()  # Convert PDU to bytes
            frame_prefix = bytes([unit_id]) + request_pdu_bytes
            crc = calculate_crc16(frame_prefix)
            request_adu = frame_prefix + crc

            log_raw_traffic("sent", request_adu)

            # 2. Wait for 3.5 character times since last frame (inter-frame delay)
            time_since_last_frame = time.monotonic() - self._last_frame_ended_at
            if time_since_last_frame < self._interframe_delay:
                to_wait = self._interframe_delay - time_since_last_frame
                await asyncio.sleep(to_wait)

            # 3. Clear receive buffer and send request
            if not self._writer:
                msg = "Connection not established."
                raise ModbusConnectionError(msg)
            self._writer.write(request_adu)
            await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)
            # 4. Receive response

            try:
                response_adu = await self._receive_response()
            except (RTUFrameError, ModbusConnectionError) as e:
                log_raw_traffic("recv", e.response_bytes, is_error=True)
                raise
            else:
                log_raw_traffic("recv", response_adu)

            # 5. Validate CRC
            if not validate_crc16(response_adu):
                raise CRCError(response_bytes=response_adu)

            # 6. Validate slave address
            if response_adu[0] != unit_id:
                msg = f"Slave address mismatch: expected {unit_id}, received {response_adu[0]}"
                raise InvalidResponseError(msg, response_bytes=response_adu)

            response_pdu = response_adu[1:-2]  # remove address and CRC

            # 7. Check if it's an exception response
            response_function_code = response_adu[1]
            if response_function_code & 0x80:  # Exception response
                function_code = response_function_code & 0x7F  # Remove exception flag bit
                exception_code = response_pdu[1] if len(response_pdu) > 1 else 0

                error_class = error_code_to_exception_map.get(exception_code, ModbusResponseError)
                raise error_class(exception_code, function_code)

            if response_function_code != pdu.function_code:
                msg = f"Function code mismatch: expected {pdu.function_code}, received {response_function_code}"
                raise InvalidResponseError(msg, response_bytes=response_adu)

            # 8. Mark the end of this frame
            self._last_frame_ended_at = time.monotonic()

            # 9. Return PDU part (remove address and CRC)
            return pdu.decode_response(response_pdu)

    async def _receive_response(self) -> bytes:
        """Receive complete response frame, using 3.5 character time as end-of-frame marker."""
        if not self._reader:
            msg = "Serial connection not established."
            raise ModbusConnectionError(msg)

        try:
            # Step 1: Read minimal header
            response_begin: bytes = await asyncio.wait_for(
                self._reader.readexactly(MIN_RTU_RESPONSE_LENGTH),
                timeout=self.timeout,
            )
        except asyncio.IncompleteReadError as e:
            msg = "Received incomplete data while reading first part of RTU frame."
            raise RTUFrameError(msg, response_bytes=e.partial) from e
        except TimeoutError:
            raise
        except Exception as e:
            msg = "Failed to read Modbus response"
            raise ModbusConnectionError(msg) from e

        # unit id in response_begin[0] is validated in send_and_receive function

        # Step 2: Determine the total expected data length for this frame
        if response_begin[1] & 0x80:  # Exception response
            # Exception response format: address + exception function code + exception code + CRC (total 5 bytes)
            expected_total_frame_length = 5
        else:
            expected_total_frame_length = (
                1  # Slave address
                + 1  # Function code
                + get_pdu_class(response_begin[1]).get_expected_response_data_length(response_begin[2:])
                + 2  # CRC
            )

        if expected_total_frame_length + len(response_begin) > MAX_RTU_FRAME_SIZE:
            msg = "Expected total RTU message frame length exceeds maximum allowed size of 256 bytes."
            raise RTUFrameError(msg, response_bytes=response_begin)

        # Step 3: Read the remaining data and CRC
        try:
            remaining_response_bytes = await asyncio.wait_for(
                self._reader.readexactly(expected_total_frame_length - len(response_begin)),
                timeout=self.timeout,
            )
        except RTUFrameError as e:
            # make sure to also pass the bytes we read at the beginning of the response in the error
            raise RTUFrameError(str(e), response_bytes=response_begin + e.response_bytes) from e
        except ModbusConnectionError as e:
            # make sure to also pass the bytes we read at the beginning of the response in the error
            raise ModbusConnectionError(str(e), bytes_read=response_begin + e.response_bytes) from e

        return response_begin + remaining_response_bytes
