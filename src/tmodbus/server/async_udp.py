"""Async Modbus UDP Server."""

import asyncio
import logging
import struct
from functools import partial
from typing import Any

from tmodbus.const import ExceptionCode
from tmodbus.exceptions import InvalidRequestError
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .base import AsyncBaseServer, get_server_pdu_class
from .handler import ModbusHandler, handle_modbus_request

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "UDP-Server")


class AsyncUdpServer(AsyncBaseServer):
    """Async Modbus UDP Server."""

    def __init__(
        self,
        host: str,
        handler: ModbusHandler,
        port: int = 502,
        *,
        unregistered_unit_id_exception_code: int = ExceptionCode.GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND,
        **server_kwargs: Any,
    ) -> None:
        """Initialize Async Modbus UDP Server.

        Args:
            host: Interface to bind to
            port: Port to listen on (default: 502)
            handler: User-defined async handler for processing requests
            unregistered_unit_id_exception_code: Exception code returned when a request is received
                for a Unit ID that is not registered in the handler (default: 0x0B).
            server_kwargs: Additional arguments for `asyncio.loop.create_datagram_endpoint`

        """
        self.host = host
        self.handler = handler
        self.port = port
        self.unregistered_unit_id_exception_code = unregistered_unit_id_exception_code
        self.server_kwargs = server_kwargs
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: ModbusUdpServerProtocol | None = None
        self._serve_forever_future: asyncio.Future[None] | None = None

    async def start(self) -> None:
        """Start the server."""
        if self._transport is not None:
            return

        loop = asyncio.get_running_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: ModbusUdpServerProtocol(self.handler, self.unregistered_unit_id_exception_code),
            local_addr=(self.host, self.port),
            **self.server_kwargs,
        )
        logger.info("Modbus UDP Server listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop the server."""
        if self._transport:
            self._transport.close()
            self._transport = None
            self._protocol = None
            logger.info("Modbus UDP Server stopped")
        if self._serve_forever_future and not self._serve_forever_future.done():
            self._serve_forever_future.set_result(None)

    async def serve_forever(self) -> None:
        """Start the server and block until cancelled."""
        await self.start()
        self._serve_forever_future = asyncio.get_running_loop().create_future()
        try:
            await self._serve_forever_future
        except asyncio.CancelledError:
            await self.stop()
            raise

    @property
    def sockets(self) -> list[Any]:
        """Get the sockets of the server (matching AsyncTcpServer sockets interface)."""
        sock = self._transport.get_extra_info("socket") if self._transport else None
        return [sock] if sock else []


class ModbusUdpServerProtocol(asyncio.DatagramProtocol):
    """Asyncio DatagramProtocol implementation for Modbus UDP Server."""

    transport: asyncio.DatagramTransport | None = None

    def __init__(
        self,
        handler: ModbusHandler,
        unregistered_unit_id_exception_code: int,
    ) -> None:
        """Initialize Modbus UDP Server Protocol."""
        super().__init__()
        self.handler = handler
        self.unregistered_unit_id_exception_code = unregistered_unit_id_exception_code
        self._background_tasks: set[asyncio.Task[None]] = set()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle connection made event."""
        if not isinstance(transport, asyncio.DatagramTransport):
            msg = "Expected a DatagramTransport"
            raise TypeError(msg)
        self.transport = transport
        logger.info("Modbus UDP server protocol endpoint established.")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Handle received datagram from client."""
        # Schedule datagram processing in the background to avoid blocking other clients
        task = asyncio.create_task(self._process_datagram(data, addr))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _process_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            if len(data) < 7:
                logger.warning("UDP packet from %s too short: %d bytes", addr, len(data))
                log_raw_traffic("recv", data, is_error=True)
                return

            mbap_header = data[:7]
            transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", mbap_header)

            if protocol_id != 0:
                logger.warning("Invalid protocol ID from %s: %d", addr, protocol_id)
                log_raw_traffic("recv", data, is_error=True)
                return

            pdu_length = length - 1  # Length includes unit_id
            if pdu_length <= 0 or pdu_length > 253:
                logger.warning("Invalid PDU length from %s: %d", addr, pdu_length)
                log_raw_traffic("recv", data, is_error=True)
                return

            if len(data) != 7 + pdu_length:
                logger.warning("UDP datagram length mismatch: expected %d, got %d", 7 + pdu_length, len(data))
                log_raw_traffic("recv", data, is_error=True)
                return

            pdu_bytes = data[7:]
            function_code = pdu_bytes[0]
            is_error = False

            if not self.handler.supports_unit_id(unit_id):
                logger.warning("Request for unregistered unit ID %d from %s", unit_id, addr)
                response_pdu_bytes = bytes([function_code | 0x80, self.unregistered_unit_id_exception_code])
                is_error = True
            else:
                try:
                    raw_pdu_class = get_server_pdu_class(pdu_bytes)
                    request_pdu = raw_pdu_class.decode_request(pdu_bytes)
                except (ValueError, InvalidRequestError) as e:
                    logger.warning("Invalid request from %s: %s", addr, e)
                    response_pdu_bytes = bytes([function_code | 0x80, 0x01])  # ILLEGAL_FUNCTION
                    is_error = True
                else:
                    response_pdu_bytes = await handle_modbus_request(unit_id, request_pdu, self.handler)

            log_raw_traffic("recv", data, is_error=is_error)

            # Build MBAP header for response
            resp_length = len(response_pdu_bytes) + 1
            resp_mbap = struct.pack(">HHHB", transaction_id, protocol_id, resp_length, unit_id)

            out_bytes = resp_mbap + response_pdu_bytes
            if self.transport:
                self.transport.sendto(out_bytes, addr)
                log_raw_traffic("sent", out_bytes)
        except Exception:
            logger.exception("Error processing UDP datagram from %s", addr)
