"""Async Modbus TCP Server."""

import asyncio
import contextlib
import logging
import struct
from functools import partial
from typing import Any

from tmodbus.exceptions import InvalidRequestError
from tmodbus.pdu import BasePDU, get_pdu_class, get_subfunction_pdu_class, is_function_code_for_subfunction_pdu
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .handler import ModbusHandler, handle_modbus_request, is_server_pdu_class

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "TCP-Server")


class AsyncTcpServer:
    """Async Modbus TCP Server."""

    def __init__(
        self,
        host: str,
        handler: ModbusHandler,
        port: int = 502,
        **server_kwargs: Any,
    ) -> None:
        """Initialize Async Modbus TCP Server.

        Args:
            host: Interface to bind to
            port: Port to listen on (default: 502)
            handler: User-defined async handler for processing requests
            server_kwargs: Additional arguments for `asyncio.start_server`

        """
        self.host = host
        self.handler = handler
        self.port = port
        self.server_kwargs = server_kwargs
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start the server."""

        self._server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            **self.server_kwargs,
        )
        logger.info("Modbus TCP Server listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop the server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("Modbus TCP Server stopped")

    async def serve_forever(self) -> None:
        """Start the server and block until cancelled."""
        await self.start()
        if self._server:
            async with self._server:
                await self._server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle a single client connection."""
        addr = writer.get_extra_info("peername")
        logger.info("Client connected: %s", addr)

        try:
            while True:
                # Read MBAP header (7 bytes)
                mbap_header = await reader.readexactly(7)
                transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", mbap_header)

                if protocol_id != 0:
                    logger.warning("Invalid protocol ID from %s: %d", addr, protocol_id)
                    break

                # Read PDU
                pdu_length = length - 1  # Length includes unit_id
                if pdu_length <= 0 or pdu_length > 253:
                    logger.warning("Invalid PDU length from %s: %d", addr, pdu_length)
                    break

                pdu_bytes = await reader.readexactly(pdu_length)

                log_raw_traffic("recv", mbap_header + pdu_bytes)

                if len(pdu_bytes) == 0:
                    continue

                function_code = pdu_bytes[0]

                try:
                    if is_function_code_for_subfunction_pdu(function_code):
                        if len(pdu_bytes) < 2:
                            msg = "Missing sub-function code"
                            raise InvalidRequestError(msg, request_bytes=pdu_bytes)
                        sub_function_code = pdu_bytes[1]
                        raw_pdu_class = get_subfunction_pdu_class(function_code, sub_function_code)
                    else:
                        raw_pdu_class = get_pdu_class(function_code)

                    if not is_server_pdu_class(raw_pdu_class):
                        msg = f"PDU class {raw_pdu_class.__name__} does not implement server methods"
                        raise ValueError(msg)

                    request_pdu = raw_pdu_class.decode_request(pdu_bytes)

                except (ValueError, InvalidRequestError) as e:
                    logger.warning("Invalid request from %s: %s", addr, e)
                    # Cannot respond if we don't even know the function code properly, or if unsupported
                    # We might reply with IllegalFunction if we at least have function_code
                    response_pdu_bytes = bytes([function_code | 0x80, 0x01])  # ILLEGAL_FUNCTION
                else:
                    if self.handler:
                        response_pdu_bytes = await handle_modbus_request(unit_id, request_pdu, self.handler)
                    else:
                        response_pdu_bytes = bytes([function_code | 0x80, 0x01])  # ILLEGAL_FUNCTION

                # Build MBAP header for response
                resp_length = len(response_pdu_bytes) + 1
                resp_mbap = struct.pack(">HHHB", transaction_id, protocol_id, resp_length, unit_id)

                out_bytes = resp_mbap + response_pdu_bytes
                writer.write(out_bytes)
                log_raw_traffic("sent", out_bytes)
                await writer.drain()

        except asyncio.IncompleteReadError:
            logger.info("Client disconnected: %s", addr)
        except Exception as e:
            logger.exception("Error handling client %s: %s", addr, e)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
