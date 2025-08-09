"""Async TCP Transport Layer Implementation.

Implements async Modbus TCP protocol transport based on asyncio, including MBAP header processing.
"""

import asyncio
import logging
import time
from typing import TypedDict, TypeVar, Unpack

import serial_asyncio

from tmodbus.exceptions import (
    CRCError,
    InvalidResponseError,
    ModbusConnectionError,
    ModbusResponseError,
    RTUFrameError,
    error_code_to_exception_map,
)
from tmodbus.pdu import BaseModbusPDU, get_pdu_class
from tmodbus.utils.crc import CRC16Modbus

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
    _last_frame_end: float = 0.0
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

    async def send_and_receive(self, unit_id: int, pdu: BaseModbusPDU[RT]) -> RT:
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
            crc = CRC16Modbus.calculate(frame_prefix)
            request_adu = frame_prefix + crc

            raw_traffic_logger.debug("RTU Send: %s", _format_bytes(request_adu))

            # 2. Wait for 3.5 character times since last frame (inter-frame delay)
            time_since_last_frame = time.monotonic() - self._last_frame_end
            if time_since_last_frame < self._interframe_delay:
                to_wait = self._interframe_delay - time_since_last_frame
                logger.debug("Waiting for inter-frame delay: %.4fs", to_wait)
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
                raw_traffic_logger.debug("RTU Receive: %s [!]", _format_bytes(e.response_bytes))
                raise
            else:
                raw_traffic_logger.debug("RTU Receive: %s", _format_bytes(response_adu))

            # 5. Validate CRC
            if not CRC16Modbus.validate(response_adu):
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
            self._last_frame_end = time.monotonic()

            # 9. Return PDU part (remove address and CRC)
            return pdu.decode_response(response_pdu)

    async def _read_continuous_transmission(self, bytes_to_read: int) -> bytes:
        """Read the rest of an RTU frame.

        We assume that this function has been called after the initial header of the RTU frame
        has been received. We now continue to read the RTU frame taking into account the
        continuous transmission requirement of the Modbus RTU standard.
        """
        if not self._reader:
            msg = "Cannot read as connection is closed."
            raise ModbusConnectionError(msg)

        buf = bytearray()

        # Read the rest of the bytes to read
        while len(buf) < bytes_to_read:
            try:
                chunk = await asyncio.wait_for(self._reader.read(1), timeout=self._max_continuous_transmission_delay)
            except TimeoutError:
                msg = (
                    "Violation of continuous transmission requirement by sender."
                    f"Missing {bytes_to_read - len(buf)} bytes to complete the frame."
                )
                raise RTUFrameError(msg, response_bytes=buf) from None
            else:
                if not chunk:
                    msg = "Serial port closed unexpectedly during response read."
                    raise ModbusConnectionError(msg, bytes_read=buf)
                buf.extend(chunk)

        # If we have read more data than expected, it indicates a framing or out-of-sync error.
        if len(buf) > bytes_to_read:
            msg = (
                "Received more data than expected while reading RTU frame. "
                f"Got {len(buf) - bytes_to_read} bytes more than expected."
            )
            raise RTUFrameError(msg, response_bytes=buf)

        return bytes(buf)

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

        # Step 2: Determine the total expected data length for this frame
        if response_begin[1] & 0x80:  # Exception response
            # Exception response format: address + exception function code + exception code + CRC (total 5 bytes)
            expected_data_length = 5
        else:
            expected_data_length = 5 + get_pdu_class(response_begin[1]).get_expected_data_length(response_begin[2:])

        # Step 3: Read the remaining data and CRC
        try:
            remaining_response_bytes = await self._read_continuous_transmission(expected_data_length)
        except RTUFrameError as e:
            # make sure to also pass the bytes we read at the beginning of the response in the error
            raise RTUFrameError(str(e), response_bytes=response_begin + e.response_bytes) from e
        except ModbusConnectionError as e:
            # make sure to also pass the bytes we read at the beginning of the response in the error
            raise ModbusConnectionError(str(e), bytes_read=response_begin + e.bytes_read) from e

        # log the current time to allow us to determine the 3.5 character gap before the next frame
        self._last_frame_end = time.monotonic()
        return response_begin + remaining_response_bytes
