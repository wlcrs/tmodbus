"""Async Modbus RTU-over-TCP Server."""

import asyncio
import contextlib
import logging
from functools import partial
from typing import Any, Literal

from tmodbus.exceptions import InvalidRequestError
from tmodbus.pdu import BasePDU, get_pdu_class, get_subfunction_pdu_class, is_function_code_for_subfunction_pdu
from tmodbus.utils.crc import calculate_crc16, validate_crc16
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .handler import ModbusHandler, handle_modbus_request, is_server_pdu_class

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "RTU-over-TCP-Server")

MAX_RTU_FRAME_SIZE = 256


class AsyncRtuOverTcpServer:
    """Async Modbus RTU-over-TCP Server.

    Incoming Data Flow & Error Branches:
    ```
    [ TCP Socket / Client Connection ]
                  │
                  ▼
         handle_client()        ────► accumulates raw data into byte buffer
                  │
                  ▼
       _process_next_frame()
                  │
                  ├──► _parse_frame_length()
                  │         ├───[ buffer < 2 bytes ]──────► returns "need_data" (reads more)
                  │         ├───[ unsupported function ]──► returns "disconnect" (clears buffer & exits)
                  │         ├───[ expected size > 256 ]───► returns "disconnect" (clears buffer & exits)
                  │         └───[ unknown length yet ]────► returns "need_data" (reads more)
                  │
                  ├───[ buffer < expected total size ]────► returns "need_data" (reads more)
                  │
                  ├───[ validate_crc16() fails ]──────────► returns "processed" (skips frame, continues loop)
                  │
                  └──► _handle_frame()
                            ├───[ PDU.decode_request() fails ]──► responds with IllegalFunction
                            └───[ Happy Path ]──────────────────► routes, encodes response & writes
                                                                  (returns "processed")
    ```
    """

    def __init__(
        self,
        host: str,
        handler: ModbusHandler,
        port: int = 502,
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
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    def _get_pdu_class(self, function_code: int, buffer: bytearray) -> type[BasePDU[Any]] | None:
        """Get the PDU class for the given function code, or None if more data is needed."""
        if is_function_code_for_subfunction_pdu(function_code):
            if len(buffer) < 3:
                return None
            sub_function_code = buffer[2]
            pdu_class = get_subfunction_pdu_class(function_code, sub_function_code)
        else:
            pdu_class = get_pdu_class(function_code)

        if not is_server_pdu_class(pdu_class):
            msg = f"PDU class {pdu_class.__name__} does not implement server methods"
            raise ValueError(msg)
        return pdu_class

    def _parse_frame_length(self, buffer: bytearray) -> int | None:
        """Parse expected total frame length from buffer, or return None if not enough data.

        Raises ValueError if unsupported function code, or frame size is too large.
        """
        if len(buffer) < 2:
            return None

        function_code = buffer[1]

        pdu_class = self._get_pdu_class(function_code, buffer)
        if pdu_class is None:
            return None

        if len(buffer) > 2:
            expected_data_len = pdu_class.get_expected_request_data_length(buffer[2:])
        else:
            return None

        expected_total_len = 1 + 1 + expected_data_len + 2  # unit_id + fc + data + crc
        if expected_total_len > MAX_RTU_FRAME_SIZE:
            msg = f"Expected frame size too large: {expected_total_len}"
            raise ValueError(msg)

        return expected_total_len

    async def _handle_frame(self, frame: bytes, addr: Any, writer: asyncio.StreamWriter) -> bool:
        """Handle a validated frame.

        Returns True if the request was successfully decoded and handled, False if it was invalid.
        """
        unit_id = frame[0]
        function_code = frame[1]
        pdu_bytes = frame[1:-2]

        pdu_class = self._get_pdu_class(function_code, bytearray(frame))
        assert pdu_class is not None

        is_error = False
        try:
            request_pdu = pdu_class.decode_request(pdu_bytes)
        except (ValueError, InvalidRequestError) as e:
            logger.warning("Invalid request from %s: %s", addr, e)
            response_pdu_bytes = bytes([function_code | 0x80, 0x01])
            is_error = True
        else:
            response_pdu_bytes = await handle_modbus_request(unit_id, request_pdu, self.handler)

        out_frame = bytearray([unit_id]) + response_pdu_bytes
        crc = calculate_crc16(out_frame)
        out_frame.extend(crc)

        writer.write(out_frame)
        log_raw_traffic("sent", out_frame)
        await writer.drain()
        return not is_error

    async def _process_next_frame(
        self, buffer: bytearray, addr: Any, writer: asyncio.StreamWriter
    ) -> Literal["need_data", "disconnect", "processed"]:
        """Process the next frame in the buffer if possible.

        Returns:
            "need_data": wait for more bytes
            "disconnect": disconnect the client
            "processed": successfully processed (or skipped a bad frame)

        """
        try:
            expected_total_len = self._parse_frame_length(buffer)
            if expected_total_len is None:
                return "need_data"
        except ValueError as e:
            logger.warning(
                "%s from %s, disconnecting client",
                e,
                addr,
            )
            log_raw_traffic("recv", bytes(buffer), is_error=True)
            buffer.clear()
            return "disconnect"

        if len(buffer) < expected_total_len:
            return "need_data"

        frame = buffer[:expected_total_len]
        del buffer[:expected_total_len]

        # Validate CRC
        if not validate_crc16(frame):
            logger.warning("CRC validation failed from %s", addr)
            log_raw_traffic("recv", frame, is_error=True)
            return "processed"

        is_success = await self._handle_frame(frame, addr, writer)
        log_raw_traffic("recv", frame, is_error=not is_success)
        return "processed"

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

                while True:
                    status = await self._process_next_frame(buffer, addr, writer)
                    if status == "need_data":
                        break
                    if status == "disconnect":
                        return
        except Exception:
            logger.exception("Error handling client %s", addr)
        finally:
            logger.info("Client disconnected: %s", addr)
            if buffer:
                log_raw_traffic("recv", bytes(buffer), is_error=True)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
