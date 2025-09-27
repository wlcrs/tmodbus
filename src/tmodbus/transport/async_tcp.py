"""Async TCP Transport Layer Implementation.

Implements async Modbus TCP protocol transport based on asyncio, including MBAP header processing.
"""

import asyncio
import logging
import struct
import time
from functools import partial
from typing import Any, TypeVar

from tmodbus.exceptions import (
    InvalidResponseError,
    ModbusConnectionError,
    ModbusResponseError,
    error_code_to_exception_map,
)
from tmodbus.pdu import BasePDU
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .async_base import AsyncBaseTransport

RT = TypeVar("RT")

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "TCP")


class AsyncTcpTransport(AsyncBaseTransport):
    """Async Modbus TCP Transport Layer Implementation.

    Handles async Modbus TCP communication based on asyncio, including:
    - Async TCP socket connection management
    - MBAP header construction and parsing
    - Transaction identifier management
    - Async error handling and timeout management
    """

    _reader: asyncio.StreamReader | None = None
    _writer: asyncio.StreamWriter | None = None
    _next_transaction_id: int = 1

    _communication_lock = asyncio.Lock()  # Prevents concurrent access to the transport layer
    _last_request_finished: float | None = None

    def __init__(
        self,
        host: str,
        port: int = 502,
        *,
        timeout: float = 10.0,
        wait_after_connect: float = 0.0,
        wait_between_requests: float = 0.0,
        **connection_kwargs: Any,
    ) -> None:
        """Initialize async TCP transport layer.

        Args:
            host: Target host IP address or domain name
            port: Target port, default 502 (Modbus TCP standard port)
            timeout: Timeout in seconds, default 10.0s
            wait_after_connect: Seconds to wait after connection establishment before making a request, default 0.0s
            wait_between_requests: Seconds to wait between consecutive requests, default 0.0s
            connection_kwargs: Additional connection parameters passed to `asyncio.open_connection` (e.g., SSL context)

        Raises:
            ValueError: When parameters are invalid
            TypeError: When parameter types are incorrect

        """
        if not 0 < port < 65535:
            msg = "Port must be an integer between 1-65535."
            raise ValueError(msg)
        if timeout <= 0:
            msg = "Timeout must be a positive number."
            raise ValueError(msg)

        self.host = host
        self.port = port
        self.timeout = timeout
        self.wait_after_connect = wait_after_connect
        self.wait_between_requests = wait_between_requests
        self.connection_kwargs = connection_kwargs

    async def open(self) -> None:
        """Async establish TCP connection."""
        async with self._communication_lock:
            if self.is_open():
                logger.debug("Async TCP connection already open: %s:%d", self.host, self.port)
                return

            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port, **self.connection_kwargs), timeout=self.timeout
                )

                logger.info("Async TCP connection established: %s:%d", self.host, self.port)
                if self.wait_after_connect > 0:
                    logger.debug(
                        "Waiting %.2f seconds after TCP connection before sending data", self.wait_after_connect
                    )
                    await asyncio.sleep(self.wait_after_connect)

            except TimeoutError:
                raise
            except Exception as e:
                raise ModbusConnectionError from e

    async def close(self) -> None:
        """Close TCP connection."""
        async with self._communication_lock:
            if not self._writer:
                logger.debug("Async TCP connection already closed: %s:%d", self.host, self.port)
                return

            try:
                self._writer.close()
                await self._writer.wait_closed()
                logger.info("Async TCP connection closed: %s:%d", self.host, self.port)
            except Exception as e:  # noqa: BLE001
                logger.debug("Error during async connection close (ignorable): %s", e)
            finally:
                self._reader = None
                self._writer = None

    def is_open(self) -> bool:
        """Async check TCP connection status."""
        if self._writer is None or self._reader is None:
            return False

        return not self._writer.is_closing()

    def _get_transaction_id(self) -> int:
        """Get the next transaction ID."""
        current_transaction_id = self._next_transaction_id
        self._next_transaction_id = (self._next_transaction_id + 1) % 0x10000  # 16-bit wraparound
        return current_transaction_id

    async def send_and_receive(self, unit_id: int, pdu: BasePDU[RT]) -> RT:
        """Async send PDU and receive response."""
        # Ensure that only one request is processed at a time
        async with self._communication_lock:
            # Wait between requests if configured to do so
            if self.wait_between_requests > 0 and self._last_request_finished is not None:
                wait_needed = self.wait_between_requests - (time.monotonic() - self._last_request_finished)
                if wait_needed > 0:
                    logger.debug(
                        "Waiting %.2fs before sending next request to respect %.2fs wait between requests",
                        wait_needed,
                        self.wait_between_requests,
                    )
                    await asyncio.sleep(wait_needed)

            try:
                return await self._do_send_and_receive(unit_id, pdu)
            finally:
                self._last_request_finished = time.monotonic()

    async def _do_send_and_receive(self, unit_id: int, pdu: BasePDU[RT]) -> RT:
        """Async send PDU and receive response.

        Implements complete async TCP protocol communication flow:
        1. Build MBAP header
        2. Async send request (MBAP header + PDU)
        3. Async receive response MBAP header
        4. Validate MBAP header
        5. Async receive response PDU
        6. Return response PDU
        """
        if not self.is_open():
            msg = "Not connected."
            raise ModbusConnectionError(msg)

        # 1. Generate transaction ID and build MBAP header
        current_transaction_id = self._get_transaction_id()

        request_pdu_bytes = pdu.encode_request()  # Convert PDU to bytes

        # MBAP header format:
        # - Transaction ID (2 bytes):  Transaction identifier
        # - Protocol ID (2 bytes): Protocol identifier, fixed to 0x0000
        # - Length (2 bytes): Length of following bytes (Unit ID + PDU)
        # - Unit ID (1 byte): Unit identifier (slave address)
        mbap_header = struct.pack(
            ">HHHB",  # Big endian: 2 shorts, 1 short, 1 byte
            current_transaction_id,  # Transaction ID
            0x0000,  # Protocol ID
            len(request_pdu_bytes) + 1,  # Length (PDU length + 1 byte for Unit ID)
            unit_id,  # Unit ID
        )

        # 2. Build complete request frame
        request_frame = mbap_header + request_pdu_bytes
        log_raw_traffic("sent", request_frame)

        # 3. Async send request
        if self._writer is None:
            msg = "Connection not established."
            raise ModbusConnectionError(msg)
        self._writer.write(request_frame)
        await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)

        # 4. Async receive response MBAP header (7 bytes)
        response_mbap = await self._receive_exact(7)

        # 5. Parse response MBAP header
        (
            response_transaction_id,
            response_protocol_id,
            response_length,
            response_unit_id,
        ) = struct.unpack(">HHHB", response_mbap)

        # 6. Validate MBAP header
        if response_transaction_id != current_transaction_id:
            msg = (
                f" Transaction ID mismatch: expected {current_transaction_id:02x}, "
                f"received {response_transaction_id:02x}"
            )
            raise InvalidResponseError(msg, response_bytes=response_mbap)

        if response_protocol_id != 0x0000:
            msg = f"Invalid Protocol ID: expected 0x0000, received 0x{response_protocol_id:04x}"
            raise InvalidResponseError(msg, response_bytes=response_mbap)

        if response_unit_id != unit_id:
            msg = f"Unit ID mismatch: expected {unit_id:02x}, received {response_unit_id:02x}"
            raise InvalidResponseError(msg, response_bytes=response_mbap)

        # 7. Async receive response PDU
        pdu_length = response_length - 1  # Subtract 1 byte for Unit ID
        if pdu_length <= 0:
            msg = f"Invalid PDU length: {pdu_length}"
            raise InvalidResponseError(msg, response_bytes=response_mbap)

        try:
            response_pdu_bytes = await self._receive_exact(pdu_length)
        except ModbusConnectionError as e:
            log_raw_traffic("recv", e.response_bytes, is_error=True)
            raise
        else:
            log_raw_traffic("recv", response_mbap + response_pdu_bytes)

        # 8.Check if it's an exception response
        if len(response_pdu_bytes) > 0 and response_pdu_bytes[0] & 0x80:  # Exception response
            function_code = response_pdu_bytes[0] & 0x7F  # Remove exception flag bit
            exception_code = response_pdu_bytes[1] if len(response_pdu_bytes) > 1 else 0

            error_class = error_code_to_exception_map.get(exception_code, ModbusResponseError)

            raise error_class(exception_code, function_code)

        return pdu.decode_response(response_pdu_bytes)

    async def _receive_exact(self, length: int) -> bytes:
        """Async receive exact length of data.

        Args:
            length: Number of bytes to receive

        Returns:
            Received data

        Raises:
            TimeoutError: Receive timeout
            ModbusConnectionError: Connection error

        """
        if self._reader is None:
            msg = "Connection not established."
            raise ModbusConnectionError(msg)

        try:
            return await asyncio.wait_for(self._reader.readexactly(length), timeout=self.timeout)
        except asyncio.IncompleteReadError as e:
            msg = f"Received incomplete data: expected {length} bytes, got {len(e.partial)} bytes"
            raise ModbusConnectionError(msg, bytes_read=e.partial) from e
        except TimeoutError as e:
            msg = f"Receive timeout: expected {length} bytes, but timed out after {self.timeout} seconds"
            raise TimeoutError(msg) from e
        except Exception as e:
            msg = f"Failed to read {length} bytes"
            raise ModbusConnectionError(msg) from e
