"""Async Modbus RTU-over-TCP Server."""

import asyncio
import contextlib
import logging
from functools import partial
from typing import Any

from tmodbus.exceptions import InvalidRequestError
from tmodbus.pdu import BasePDU, get_pdu_class, get_subfunction_pdu_class, is_function_code_for_subfunction_pdu
from tmodbus.utils.crc import calculate_crc16, validate_crc16
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .handler import ModbusRequestHandler, ModbusService

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "RTU-over-TCP-Server")

MAX_RTU_FRAME_SIZE = 256


class AsyncRtuOverTcpServer:
    """Async Modbus RTU-over-TCP Server."""

    def __init__(
        self,
        host: str,
        port: int = 502,
        handler: ModbusService | None = None,
        **server_kwargs: Any,
    ) -> None:
        """Initialize Async Modbus RTU-over-TCP Server.

        Args:
            host: Interface to bind to
            port: Port to listen on (default: 502)
            handler: User-defined async handler for processing requests
            server_kwargs: Additional arguments for `asyncio.start_server`

        """
        self.host = host
        self.port = port
        self.handler = handler
        self.server_kwargs = server_kwargs
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start the server."""
        if self.handler is None:
            msg = "No handler specified for Modbus Server"
            raise ValueError(msg)

        self._server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            **self.server_kwargs,
        )
        logger.info("Modbus RTU-over-TCP Server listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop the server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("Modbus RTU-over-TCP Server stopped")

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

        buffer = bytearray()

        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                buffer.extend(data)

                while len(buffer) >= 2:
                    unit_id = buffer[0]
                    function_code = buffer[1]

                    try:
                        if is_function_code_for_subfunction_pdu(function_code):
                            if len(buffer) < 3:
                                break  # Wait for more data
                            sub_function_code = buffer[2]
                            pdu_class = get_subfunction_pdu_class(function_code, sub_function_code)
                        else:
                            pdu_class = get_pdu_class(function_code)  # type: ignore[assignment]

                        if not issubclass(pdu_class, BasePDU):
                            msg = f"PDU class {pdu_class.__name__} does not implement server methods"
                            raise ValueError(msg)

                    except ValueError:
                        logger.warning("Unsupported function code %02X from %s, clearing buffer", function_code, addr)
                        buffer.clear()
                        break

                    if len(buffer) > 2:
                        expected_data_len = pdu_class.get_expected_request_data_length(buffer[2:])
                    else:
                        break  # Wait for more data

                    expected_total_len = 1 + 1 + expected_data_len + 2  # unit_id + fc + data + crc

                    if expected_total_len > MAX_RTU_FRAME_SIZE:
                        logger.warning("Expected frame size too large from %s: %d", addr, expected_total_len)
                        buffer.clear()
                        break

                    if len(buffer) < expected_total_len:
                        break  # Wait for more data

                    frame = buffer[:expected_total_len]
                    buffer = buffer[expected_total_len:]

                    log_raw_traffic("recv", frame)

                    if not validate_crc16(frame):
                        logger.warning("CRC validation failed from %s", addr)
                        continue

                    pdu_bytes = frame[1:-2]
                    try:
                        request_pdu = pdu_class.decode_request(pdu_bytes)
                    except InvalidRequestError as e:
                        logger.warning("Invalid request from %s: %s", addr, e)
                        response_pdu_bytes = bytes([function_code | 0x80, 0x01])
                    else:
                        if self.handler:
                            response_pdu_bytes = await ModbusRequestHandler(unit_id, request_pdu, self.handler)
                        else:
                            response_pdu_bytes = bytes([function_code | 0x80, 0x01])

                    out_frame = bytearray([unit_id]) + response_pdu_bytes
                    crc = calculate_crc16(out_frame)
                    out_frame.extend(crc)

                    writer.write(out_frame)
                    log_raw_traffic("sent", out_frame)
                    await writer.drain()

        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.exception("Error handling client %s: %s", addr, e)
        finally:
            logger.info("Client disconnected: %s", addr)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
