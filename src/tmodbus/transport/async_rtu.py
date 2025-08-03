"""Async TCP Transport Layer Implementation.

Implements async Modbus TCP protocol transport based on asyncio, including MBAP header processing.
"""

import asyncio
import logging
from typing import TypedDict, TypeVar, Unpack

import serial_asyncio

from tmodbus.exceptions import (
    CRCError,
    InvalidResponseError,
    ModbusConnectionError,
    ModbusResponseError,
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
    _next_transaction_id: int = 1

    _communication_lock = asyncio.Lock()  # Prevents concurrent access to the transport layer

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
        2. Send request
        3. Receive response
        4. Validate CRC
        5. Return response PDU
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

            # 2. Clear receive buffer and send request
            if not self._writer:
                msg = "Connection not established."
                raise ModbusConnectionError(msg)
            self._writer.write(request_adu)
            await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)

            # 3. Receive response
            response_adu = await self._receive_response()

            raw_traffic_logger.debug("RTU Receive: %s", _format_bytes(response_adu))

            # 4. Validate CRC
            if not CRC16Modbus.validate(response_adu):
                raise CRCError

            # 5. Validate slave address
            if response_adu[0] != unit_id:
                msg = f"Slave address mismatch: expected {unit_id}, received {response_adu[0]}"
                raise InvalidResponseError(msg)

            response_pdu = response_adu[1:-2]  # remove address and CRC

            # 6. Check if it's an exception response
            response_function_code = response_adu[0]
            if response_function_code & 0x80:  # Exception response
                function_code = response_function_code & 0x7F  # Remove exception flag bit
                exception_code = response_pdu[1] if len(response_pdu) > 1 else 0

                error_class = error_code_to_exception_map.get(exception_code, ModbusResponseError)
                raise error_class(exception_code, function_code)

            if response_function_code != pdu.function_code:
                msg = f"Function code mismatch: expected {pdu.function_code}, received {response_function_code}"
                raise InvalidResponseError(msg)

            # 7. Return PDU part (remove address and CRC)
            return pdu.decode_response(response_pdu)

    async def _receive_response(self) -> bytes:
        """Receive complete response frame."""
        if not self._reader:
            msg = "Serial connection not established."
            raise ModbusConnectionError(msg)

        try:
            response_begin: bytes = await asyncio.wait_for(
                self._reader.readexactly(MIN_RTU_RESPONSE_LENGTH),
                timeout=self.timeout,
            )

            #  Check if it's an exception response
            if response_begin[1] & 0x80:  #  Exception response
                # Exception response format: address + exception function code + exception code + CRC (total 5 bytes)

                return response_begin + await asyncio.wait_for(
                    self._reader.readexactly(5 - MIN_RTU_RESPONSE_LENGTH),  # we need only 1 more byte
                    timeout=self.timeout,
                )  # Exception code + CRC

            # Normal response format: address + function code + data + CRC

            # figure out how many more bytes to read
            expected_data_length = get_pdu_class(response_begin[1]).get_expected_data_length(response_begin[2:])

            # we already read the minimal response length (taking into account address, function code, and CRC)
            # now we only need to read the length of the data part too

            return response_begin + await asyncio.wait_for(
                self._reader.readexactly(expected_data_length),
                timeout=self.timeout,
            )

        except asyncio.IncompleteReadError as e:
            msg = "Received incomplete data"
            raise ModbusConnectionError(msg) from e
        except TimeoutError:
            raise
        except Exception as e:
            msg = "Failed to read Modbus response"
            raise ModbusConnectionError(msg) from e
