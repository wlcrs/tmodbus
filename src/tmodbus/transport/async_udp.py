"""Async UDP Transport Layer Implementation.

Implements async Modbus UDP protocol transport based on asyncio, including MBAP header processing.
"""

import asyncio
import logging
import struct
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import Any, TypeVar

from tmodbus.exceptions import (
    InvalidResponseError,
    ModbusConnectionError,
    UnknownModbusResponseError,
    error_code_to_exception_map,
)
from tmodbus.pdu import BaseClientPDU
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .async_base import AsyncBaseTransport

RT = TypeVar("RT")

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "UDP")


class AsyncUdpTransport(AsyncBaseTransport):
    """Async Modbus UDP Transport Layer Implementation.

    Handles async Modbus UDP communication based on asyncio, including:
    - Async UDP socket connection management (using create_datagram_endpoint)
    - MBAP header construction and parsing
    - Transaction identifier management
    - Async error handling and timeout management
    """

    _transport: asyncio.DatagramTransport | None = None
    _protocol: "ModbusUdpProtocol | None" = None

    def __init__(
        self,
        host: str,
        port: int = 502,
        *,
        timeout: float = 10.0,
        connect_timeout: float = 10.0,
        on_connection_lost: Callable[[Exception | None], None] | None = None,
        **connection_kwargs: Any,
    ) -> None:
        """Initialize async UDP transport layer.

        Args:
            host: Target host IP address or domain name
            port: Target port, default 502 (Modbus TCP/UDP standard port)
            timeout: Timeout in seconds, default 10.0s
            connect_timeout: Timeout for establishing connection, default 10.0s
            on_connection_lost: Optional callback invoked the moment the connection is lost.
                                Receives the causing exception, or None on a clean close.
            connection_kwargs: Additional connection parameters passed to `asyncio.create_datagram_endpoint`

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
        if connect_timeout <= 0:
            msg = "Connect timeout must be a positive number."
            raise ValueError(msg)

        self.host = host
        self.port = port
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.on_connection_lost = on_connection_lost
        self.connection_kwargs = connection_kwargs

    async def open(self) -> None:
        """Async establish UDP endpoint."""
        loop = asyncio.get_running_loop()
        if self.is_open():
            logger.debug("Async UDP connection already open: %s:%d", self.host, self.port)
            return

        try:
            self._transport, self._protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    lambda: ModbusUdpProtocol(on_connection_lost=self._on_connection_lost, timeout=self.timeout),
                    remote_addr=(self.host, self.port),
                    **self.connection_kwargs,
                ),
                timeout=self.connect_timeout,
            )

            logger.info("Async UDP endpoint established: %s:%d", self.host, self.port)
        except TimeoutError:
            logger.warning("Async UDP endpoint creation timeout: %s:%d", self.host, self.port, exc_info=True)
            raise
        except Exception as e:
            logger.exception("Async UDP endpoint creation error: %s:%d", self.host, self.port)
            raise ModbusConnectionError from e

    async def close(self) -> None:
        """Close UDP transport."""
        if not self._transport or self._transport.is_closing():
            logger.debug("Async UDP connection already closed: %s:%d", self.host, self.port)
            return

        try:
            self._transport.close()
            logger.info("Async UDP connection closed: %s:%d", self.host, self.port)
        except Exception as e:  # noqa: BLE001
            logger.debug("Error during async connection close: %s", e)

    def is_open(self) -> bool:
        """Check if UDP connection is open."""
        return self._transport is not None and not self._transport.is_closing()

    def _on_connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.error("Async UDP connection lost due to error: %s", exc)
        else:
            logger.info("Async UDP connection closed.")

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
class _ModbusMessage:
    """Dataclass representing a Modbus message with MBAP header and PDU."""

    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int
    pdu_bytes: bytes

    @property
    def bytes(self) -> bytes:
        """Get full message bytes including MBAP header and PDU."""
        mbap_header = struct.pack(">HHHB", self.transaction_id, self.protocol_id, self.length, self.unit_id)
        return mbap_header + self.pdu_bytes


class ModbusUdpProtocol(asyncio.DatagramProtocol):
    """Asyncio DatagramProtocol implementation for Modbus UDP with MBAP headers."""

    transport: asyncio.DatagramTransport | None = None

    on_connection_lost: Callable[[Exception | None], None]
    timeout: float

    _next_transaction_id: int
    _pending_requests: dict[int, asyncio.Future[_ModbusMessage]]

    def __init__(
        self,
        *,
        on_connection_lost: Callable[[Exception | None], None],
        timeout: float = 10.0,
    ) -> None:
        """Initialize Modbus UDP Protocol."""
        super().__init__()

        self.on_connection_lost = on_connection_lost
        self.timeout = timeout

        self._next_transaction_id = 1
        self._pending_requests = {}

    def _get_next_transaction_id(self) -> int:
        current_id = self._next_transaction_id
        self._next_transaction_id = (self._next_transaction_id + 1) % 0x10000  # 16-bit wraparound
        return current_id

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle connection made event."""
        if not isinstance(transport, asyncio.DatagramTransport):
            msg = "Expected a DatagramTransport"
            raise TypeError(msg)

        self.transport = transport
        logger.info("Modbus UDP protocol connection established.")

    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        """Async send PDU and receive response.

        Implements complete async UDP protocol communication flow:
        1. Build MBAP header
        2. Async send request (MBAP header + PDU)
        3. Async wait for response matched by Transaction ID
        4. Validate MBAP header
        5. Return response PDU
        """
        if self.transport is None or self.transport.is_closing():
            msg = "Not connected."
            raise ModbusConnectionError(msg)

        current_transaction_id = self._get_next_transaction_id()
        request_pdu_bytes = pdu.encode_request()  # Convert PDU to bytes

        mbap_header = struct.pack(
            ">HHHB",
            current_transaction_id,
            0x0000,
            len(request_pdu_bytes) + 1,
            unit_id,
        )

        request_frame = mbap_header + request_pdu_bytes

        read_future: asyncio.Future[_ModbusMessage] = asyncio.get_event_loop().create_future()
        self._pending_requests[current_transaction_id] = read_future

        self.transport.sendto(request_frame)
        log_raw_traffic("sent", request_frame)

        try:
            response = await asyncio.wait_for(read_future, timeout=self.timeout)
        except TimeoutError as e:
            msg = f"Response timeout after {self.timeout} seconds for transaction with ID {current_transaction_id:#04x}"
            raise TimeoutError(msg) from e
        finally:
            self._pending_requests.pop(current_transaction_id, None)

        if response.unit_id != unit_id:
            msg = f"Unit ID mismatch: expected {unit_id:#04x}, received {response.unit_id:#04x}"
            raise InvalidResponseError(msg, response_bytes=response.bytes)

        if len(response.pdu_bytes) > 0 and response.pdu_bytes[0] & 0x80:  # Exception response
            function_code = response.pdu_bytes[0] & 0x7F
            exception_code = response.pdu_bytes[1] if len(response.pdu_bytes) > 1 else 0

            if exception_code in error_code_to_exception_map:
                raise error_code_to_exception_map[exception_code](function_code)
            raise UnknownModbusResponseError(exception_code, function_code)

        return pdu.decode_response(response.pdu_bytes)

    def datagram_received(self, data: bytes, _addr: tuple[str, int] | None) -> None:
        """Handle incoming datagram."""
        if len(data) < 7:
            logger.warning("Received UDP packet too short: %d bytes", len(data))
            log_raw_traffic("recv", data, is_error=True)
            return

        transaction_id, protocol_id, length, unit_id = struct.unpack_from(">HHHB", data)

        if protocol_id != 0x0000:
            logger.warning("Received UDP packet with invalid Protocol ID: %d", protocol_id)
            log_raw_traffic("recv", data, is_error=True)
            return

        pdu_length = length - 1
        if len(data) != 7 + pdu_length:
            logger.warning("Received UDP packet length mismatch: expected %d, got %d", 7 + pdu_length, len(data))
            log_raw_traffic("recv", data, is_error=True)
            return

        pdu_bytes = data[7:]

        future = self._pending_requests.get(transaction_id)
        if future and not future.done():
            log_raw_traffic("recv", data)
            future.set_result(
                _ModbusMessage(
                    transaction_id=transaction_id,
                    protocol_id=protocol_id,
                    length=length,
                    unit_id=unit_id,
                    pdu_bytes=pdu_bytes,
                )
            )
        else:
            logger.warning(
                "Received unexpected response with Transaction ID: %d. Discarding bytes: %s",
                transaction_id,
                data.hex(" ").upper(),
            )
            log_raw_traffic("recv", data, is_ignored=True)

    def error_received(self, exc: Exception) -> None:
        """Handle error received (e.g. ICMP port unreachable)."""
        logger.warning("Modbus UDP protocol error received: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        """Handle connection lost event."""
        for future in self._pending_requests.values():
            if not future.done():
                future.set_exception(ModbusConnectionError("Connection lost before response was received."))
        self._pending_requests.clear()

        self.on_connection_lost(exc)


__all__ = ["AsyncUdpTransport"]
