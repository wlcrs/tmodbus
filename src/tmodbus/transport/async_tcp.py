"""Async TCP Transport Layer Implementation.

Implements async Modbus TCP protocol transport based on asyncio, including MBAP header processing.
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
log_raw_traffic = partial(base_log_raw_traffic, "TCP")


class AsyncTcpTransport(AsyncBaseTransport):
    """Async Modbus TCP Transport Layer Implementation.

    Handles async Modbus TCP communication based on asyncio, including:
    - Async TCP socket connection management
    - MBAP header construction and parsing
    - Transaction identifier management
    - Async error handling and timeout management
    """

    _transport: asyncio.Transport | None = None
    _protocol: "ModbusTcpProtocol | None" = None

    def __init__(
        self,
        host: str,
        port: int = 502,
        *,
        timeout: float = 10.0,
        connect_timeout: float = 10.0,
        **connection_kwargs: Any,
    ) -> None:
        """Initialize async TCP transport layer.

        Args:
            host: Target host IP address or domain name
            port: Target port, default 502 (Modbus TCP standard port)
            timeout: Timeout in seconds, default 10.0s
            connect_timeout: Timeout for establishing connection, default 10.0s
            connection_kwargs: Additional connection parameters passed to `asyncio.create_connection`
                               (e.g., SSL context)

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
        self.connection_kwargs = connection_kwargs

    async def open(self) -> None:
        """Async establish TCP connection."""
        loop = asyncio.get_running_loop()
        if self.is_open():
            logger.debug("Async TCP connection already open: %s:%d", self.host, self.port)
            return

        try:
            self._transport, self._protocol = await loop.create_connection(
                lambda: ModbusTcpProtocol(on_connection_lost=self._on_connection_lost, timeout=self.timeout),
                host=self.host,
                port=self.port,
                **self.connection_kwargs,
            )

            logger.info("Async TCP connection established: %s:%d", self.host, self.port)
        except TimeoutError:
            logger.warning("Async TCP connection timeout: %s:%d", self.host, self.port, exc_info=True)
            raise
        except Exception as e:
            logger.exception("Async TCP connection error: %s:%d", self.host, self.port)
            raise ModbusConnectionError from e

    async def close(self) -> None:
        """Close TCP connection."""
        if not self._transport or self._transport.is_closing():
            logger.debug("Async TCP connection already closed: %s:%d", self.host, self.port)
            return

        try:
            self._transport.close()
            logger.info("Async TCP connection closed: %s:%d", self.host, self.port)
        except Exception as e:  # noqa: BLE001
            logger.debug("Error during async connection close: %s", e)

    def is_open(self) -> bool:
        """Check if TCP connection is open."""
        return self._transport is not None and not self._transport.is_closing()

    def _on_connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.error("Async TCP connection lost due to error: %s", exc)
        else:
            logger.info("Async TCP connection closed by remote host.")

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


class ModbusTcpProtocol(asyncio.Protocol):
    """Asyncio Protocol implementation for Modbus TCP with MBAP headers."""

    transport: "asyncio.WriteTransport | None" = None

    on_connection_lost: Callable[[Exception | None], None]
    timeout: float

    _on_con_lost: asyncio.Future[Exception | None]
    _buffer: bytearray
    _next_transaction_id: int
    _transaction_id_lock: asyncio.Lock
    _last_request_finished_at: float = 0.0
    _pending_requests: dict[int, asyncio.Future[_ModbusMessage]]

    def __init__(
        self,
        *,
        on_connection_lost: Callable[[Exception | None], None],
        timeout: float = 10.0,
    ) -> None:
        """Initialize Modbus TCP Protocol."""
        super().__init__()

        self.on_connection_lost = on_connection_lost
        self.timeout = timeout

        self._on_con_lost = asyncio.get_event_loop().create_future()
        self._buffer = bytearray()
        self._next_transaction_id = 1
        self._transaction_id_lock = asyncio.Lock()
        self._pending_requests = {}

    async def _get_next_transaction_id(self) -> int:
        async with self._transaction_id_lock:
            current_id = self._next_transaction_id
            self._next_transaction_id = (self._next_transaction_id + 1) % 0x10000  # 16-bit wraparound
            return current_id

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle connection made event."""
        if not isinstance(transport, asyncio.WriteTransport):
            msg = "Expected a WriteTransport"
            raise TypeError(msg)

        self.transport = transport
        logger.info("Modbus TCP protocol connection established.")

    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        """Async send PDU and receive response.

        Implements complete async TCP protocol communication flow:
        1. Build MBAP header
        2. Async send request (MBAP header + PDU)
        3. Async receive response MBAP header
        4. Validate MBAP header
        5. Async receive response PDU
        6. Return response PDU
        """
        if self.transport is None or self.transport.is_closing():
            msg = "Not connected."
            raise ModbusConnectionError(msg)

        # 1. Generate transaction ID and build MBAP header
        current_transaction_id = await self._get_next_transaction_id()

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

        # 3. Async send request
        read_future: asyncio.Future[_ModbusMessage] = asyncio.get_event_loop().create_future()
        self._pending_requests[current_transaction_id] = read_future

        self.transport.write(request_frame)
        log_raw_traffic("sent", request_frame)

        # 4. Async wait for response or timeout
        try:
            response = await asyncio.wait_for(read_future, timeout=self.timeout)
        except TimeoutError as e:
            msg = f"Response timeout after {self.timeout} seconds for transaction with ID {current_transaction_id:#04x}"
            raise TimeoutError(msg) from e
        finally:
            self._pending_requests.pop(current_transaction_id, None)

        # 6. Validate MBAP header
        # We can skip checking the transaction ID: it was used to match the response to the read_future
        # of this request.

        # We can also skip checking the protocol ID: the parser already discarded any message with a
        # different protocol ID.

        if response.unit_id != unit_id:
            msg = f"Unit ID mismatch: expected {unit_id:#04x}, received {response.unit_id:#04x}"
            raise InvalidResponseError(msg, response_bytes=response.bytes)

        # 8.Check if it's an exception response
        if len(response.pdu_bytes) > 0 and response.pdu_bytes[0] & 0x80:  # Exception response
            function_code = response.pdu_bytes[0] & 0x7F  # Remove exception flag bit
            exception_code = response.pdu_bytes[1] if len(response.pdu_bytes) > 1 else 0

            error_class = error_code_to_exception_map.get(exception_code, UnknownModbusResponseError)
            raise error_class(exception_code, function_code)

        return pdu.decode_response(response.pdu_bytes)

    def data_received(self, data: bytes) -> None:
        """Handle data received event."""
        self._buffer.extend(data)
        log_raw_traffic("recv", data)

        first_message_incomplete = False
        # Check if we have enough data for MBAP header
        while (
            len(self._buffer) >= 7  # MBAP header is 7 bytes
            and not first_message_incomplete  # stop when the first message in the buffer is not complete yet
        ):
            # Unpack MBAP header
            transaction_id, protocol_id, length, unit_id = struct.unpack_from(">HHHB", self._buffer)

            # Do some sanity checks on the contents of the header: can it be the start of a valid message?
            if protocol_id != 0x0000:
                # Unexpected contents: let's try to discard as much as needed to find a valid header
                # We look for the next occurrence of 0x0000 in the buffer
                next_protocol_id_pos = self._buffer.find(b"\x00\x00", 2)  # start searching after the first 2 bytes
                if next_protocol_id_pos == -1:
                    # No occurrence found: discard everything except the last byte (in case it's part of a valid header)
                    logger.debug("Discarding garbage bytes: %s", self._buffer[:-1].hex(" ").upper())
                    del self._buffer[:-1]
                    return  # buffer is exhausted, wait for more data

                # Discard bytes up to the potential start of the next message
                logger.debug("Discarding garbage bytes: %s", self._buffer[:next_protocol_id_pos].hex(" ").upper())
                # keep the 2 bytes before the found occurrence, as it contains the transaction ID
                del self._buffer[: next_protocol_id_pos - 2]
                continue  # Re-evaluate the buffer from the start

            # we have a valid protocol ID, now check if we have the full message

            total_length = 7 + (length - 1)  # Total length = MBAP header + PDU length

            if len(self._buffer) >= total_length:
                # Extract complete response
                response = bytes(self._buffer[:total_length])
                del self._buffer[:total_length]

                # Match response to pending request
                future = self._pending_requests.get(transaction_id)
                if future and not future.done():
                    future.set_result(
                        _ModbusMessage(
                            transaction_id=transaction_id,
                            protocol_id=protocol_id,
                            length=length,
                            unit_id=unit_id,
                            pdu_bytes=response[7:],  # PDU starts after MBAP header
                        )
                    )
                else:
                    logger.warning(
                        "Received unexpected response with Transaction ID: %d. Discarding bytes: %s",
                        transaction_id,
                        response.hex(" ").upper(),
                    )
            else:
                first_message_incomplete = True

    def connection_lost(self, exc: Exception | None) -> None:
        """Handle connection lost event."""
        for future in self._pending_requests.values():
            if not future.done():
                future.set_exception(ModbusConnectionError("Connection lost before response was received."))
        self._pending_requests.clear()

        self.on_connection_lost(exc)


__all__ = ["AsyncTcpTransport"]
