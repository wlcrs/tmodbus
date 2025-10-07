"""Async RTU over TCP Transport Layer Implementation.

Implements Modbus RTU over TCP protocol transport, which uses:
- TCP/IP for the network layer (like standard Modbus TCP)
- RTU framing with CRC-16 for the data layer (instead of MBAP header)

This is useful for serial-to-Ethernet converters that encapsulate RTU frames
in TCP packets without converting to Modbus TCP format.
"""

import asyncio
import logging
from functools import partial
from typing import Any, TypeVar

from tmodbus.exceptions import (
    CRCError,
    InvalidResponseError,
    ModbusConnectionError,
    RTUFrameError,
    UnknownModbusResponseError,
    error_code_to_exception_map,
)
from tmodbus.pdu import BaseClientPDU, get_pdu_class
from tmodbus.utils.crc import calculate_crc16, validate_crc16
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .async_base import AsyncBaseTransport

RT = TypeVar("RT")

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "RTU/TCP")

MAX_RTU_FRAME_SIZE = 256  # Maximum RTU frame size in bytes
MIN_RTU_RESPONSE_LENGTH = 4  # Minimal response: address + function code + CRC (2 bytes)


class AsyncRtuOverTcpTransport(AsyncBaseTransport):
    """Async Modbus RTU over TCP Transport Layer Implementation.

    Handles async Modbus RTU over TCP communication, combining:
    - TCP connection management (like AsyncTcpTransport)
    - RTU framing with CRC-16 validation (like AsyncRtuTransport)

    This transport is used for serial-to-Ethernet converters that forward
    RTU frames over TCP without converting them to Modbus TCP format.
    """

    _reader: asyncio.StreamReader | None = None
    _writer: asyncio.StreamWriter | None = None
    _communication_lock = asyncio.Lock()

    def __init__(
        self,
        host: str,
        port: int = 502,
        *,
        timeout: float = 10.0,
        connect_timeout: float = 10.0,
        **connection_kwargs: Any,
    ) -> None:
        """Initialize async RTU over TCP transport layer.

        Args:
            host: Target host IP address or domain name
            port: Target port, default 502 (Modbus TCP standard port)
            timeout: Timeout in seconds for read/write operations, default 10.0s
            connect_timeout: Timeout for establishing connection, default 10.0s
            connection_kwargs: Additional connection parameters passed to `asyncio.open_connection`

        Raises:
            ValueError: When parameters are invalid

        """
        if not 0 < port < 65535:
            msg = "Port must be an integer between 1-65535."
            raise ValueError(msg)
        if timeout <= 0:
            msg = "Timeout must be a positive number."
            raise ValueError(msg)
        if connect_timeout <= 0:
            msg = "Connect timeout must be a positive number."
            raise ValueError(msg)

        self.host = host
        self.port = port
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.connection_kwargs = connection_kwargs

    async def open(self) -> None:
        """Establish TCP connection."""
        async with self._communication_lock:
            if self.is_open():
                logger.debug("RTU/TCP connection already open: %s:%d", self.host, self.port)
                return

            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port, **self.connection_kwargs),
                    timeout=self.connect_timeout,
                )
                logger.info("RTU/TCP connection established: %s:%d", self.host, self.port)
            except TimeoutError:
                logger.warning("RTU/TCP connection timeout: %s:%d", self.host, self.port, exc_info=True)
                raise
            except Exception as e:
                logger.exception("RTU/TCP connection error: %s:%d", self.host, self.port)
                raise ModbusConnectionError from e

    async def close(self) -> None:
        """Close TCP connection."""
        async with self._communication_lock:
            if not self._writer:
                logger.debug("RTU/TCP connection already closed: %s:%d", self.host, self.port)
                return

            try:
                self._writer.close()
                await self._writer.wait_closed()
                logger.info("RTU/TCP connection closed: %s:%d", self.host, self.port)
            except Exception as e:  # noqa: BLE001
                logger.debug("Error during RTU/TCP connection close (ignorable): %s", e)
            finally:
                self._reader = None
                self._writer = None

    def is_open(self) -> bool:
        """Check TCP connection status."""
        if self._writer is None or self._reader is None:
            return False
        return not self._writer.is_closing()

    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        """Send PDU and receive response using RTU framing over TCP.

        Implements complete RTU over TCP protocol communication flow:
        1. Build RTU frame (Address + PDU + CRC)
        2. Send request over TCP
        3. Receive response from TCP
        4. Validate CRC
        5. Return response PDU

        Args:
            unit_id: Modbus unit/slave address
            pdu: PDU object to send

        Returns:
            Decoded response data

        Raises:
            ModbusConnectionError: Connection issues
            CRCError: CRC validation failed
            InvalidResponseError: Invalid response received

        """
        async with self._communication_lock:
            if not self.is_open():
                msg = "Not connected."
                raise ModbusConnectionError(msg)

            # 1. Build request frame with RTU framing
            request_pdu_bytes = pdu.encode_request()
            frame_prefix = bytes([unit_id]) + request_pdu_bytes
            crc = calculate_crc16(frame_prefix)
            request_adu = frame_prefix + crc

            log_raw_traffic("sent", request_adu)

            # 2. Send request over TCP
            if not self._writer:
                msg = "Connection not established."
                raise ModbusConnectionError(msg)

            self._writer.write(request_adu)
            await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)

            # 3. Receive response
            try:
                response_adu = await self._receive_response()
            except (RTUFrameError, ModbusConnectionError) as e:
                log_raw_traffic("recv", e.response_bytes, is_error=True)
                raise
            else:
                log_raw_traffic("recv", response_adu)

            # 4. Validate CRC
            if not validate_crc16(response_adu):
                raise CRCError(response_bytes=response_adu)

            # 5. Validate slave address
            if response_adu[0] != unit_id:
                msg = f"Slave address mismatch: expected {unit_id}, received {response_adu[0]}"
                raise InvalidResponseError(msg, response_bytes=response_adu)

            # 6. Extract response PDU (remove address and CRC)
            response_pdu = response_adu[1:-2]

            # 7. Check if it's an exception response
            response_function_code = response_adu[1]
            if response_function_code & 0x80:
                function_code = response_function_code & 0x7F
                exception_code = response_pdu[1] if len(response_pdu) > 1 else 0

                error_class = error_code_to_exception_map.get(exception_code, UnknownModbusResponseError)
                raise error_class(exception_code, function_code)

            if response_function_code != pdu.function_code:
                msg = f"Function code mismatch: expected {pdu.function_code}, received {response_function_code}"
                raise InvalidResponseError(msg, response_bytes=response_adu)

            # 8. Return decoded response
            return pdu.decode_response(response_pdu)

    async def _receive_response(self) -> bytes:
        """Receive complete RTU response frame over TCP.

        Returns:
            Complete RTU frame including address, PDU, and CRC

        Raises:
            RTUFrameError: Invalid frame received
            ModbusConnectionError: Connection error

        """
        if not self._reader:
            msg = "TCP connection not established."
            raise ModbusConnectionError(msg)

        # Step 1: Read minimal header (address + function code + minimum data)
        response_begin = await self._read_response_header()

        # Step 2: Determine the total expected frame length
        expected_total_frame_length = self._calculate_expected_frame_length(response_begin)

        if expected_total_frame_length > MAX_RTU_FRAME_SIZE:
            msg = (
                f"Expected frame length {expected_total_frame_length} "
                f"exceeds maximum RTU frame size {MAX_RTU_FRAME_SIZE}."
            )
            raise RTUFrameError(msg, response_bytes=response_begin)

        # Step 3: Read the remaining bytes
        remaining_bytes_to_read = expected_total_frame_length - len(response_begin)

        if remaining_bytes_to_read <= 0:
            return response_begin

        remaining_response_bytes = await self._read_remaining_bytes(remaining_bytes_to_read, response_begin)
        return response_begin + remaining_response_bytes

    async def _read_response_header(self) -> bytes:
        """Read the minimal RTU response header.

        Returns:
            Initial bytes of the response (address + function code + minimum data)

        Raises:
            RTUFrameError: Error reading header
            ModbusConnectionError: Connection error

        """
        try:
            return await asyncio.wait_for(
                self._reader.readexactly(MIN_RTU_RESPONSE_LENGTH),  # type: ignore[union-attr]
                timeout=self.timeout,
            )
        except asyncio.IncompleteReadError as e:
            msg = "Received incomplete data while reading first part of RTU frame."
            raise RTUFrameError(msg, response_bytes=e.partial) from e
        except TimeoutError:
            raise
        except Exception as e:
            msg = "Failed to read Modbus RTU response"
            raise ModbusConnectionError(msg) from e

    def _calculate_expected_frame_length(self, response_begin: bytes) -> int:
        """Calculate the expected total frame length based on the response header.

        Args:
            response_begin: Initial bytes of the response

        Returns:
            Expected total frame length in bytes

        """
        if response_begin[1] & 0x80:  # Exception response
            # Exception response format: address + exception function code + exception code + CRC (5 bytes total)
            return 5

        # Normal response: address + function code + data + CRC
        return (
            1  # Slave address
            + 1  # Function code
            + get_pdu_class(response_begin[1:2]).get_expected_response_data_length(response_begin[2:])
            + 2  # CRC
        )

    async def _read_remaining_bytes(self, remaining_bytes_to_read: int, response_begin: bytes) -> bytes:
        """Read the remaining bytes of the RTU frame.

        Args:
            remaining_bytes_to_read: Number of bytes still to read
            response_begin: Initial bytes already read (for error reporting)

        Returns:
            Remaining bytes of the frame

        Raises:
            RTUFrameError: Error reading remaining bytes
            ModbusConnectionError: Connection error

        """
        try:
            return await asyncio.wait_for(
                self._reader.readexactly(remaining_bytes_to_read),  # type: ignore[union-attr]
                timeout=self.timeout,
            )
        except asyncio.IncompleteReadError as e:
            msg = f"Received incomplete data: expected {remaining_bytes_to_read} more bytes, got {len(e.partial)} bytes"
            raise RTUFrameError(msg, response_bytes=response_begin + e.partial) from e
        except TimeoutError:
            raise
        except Exception as e:
            msg = "Failed to read remaining RTU frame bytes"
            raise ModbusConnectionError(msg) from e
