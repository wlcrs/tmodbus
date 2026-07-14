"""Async Modbus ASCII Server."""

import asyncio
import contextlib
import logging
from functools import partial
from typing import Any, Literal

from serialx import open_serial_connection

from tmodbus.exceptions import InvalidRequestError
from tmodbus.utils.lrc import calculate_lrc, validate_lrc
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .base import AsyncBaseServer, get_server_pdu_class
from .handler import ModbusHandler, handle_modbus_request

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "ASCII-Server")


class AsyncAsciiServer(AsyncBaseServer):
    r"""Async Modbus ASCII Server.

    Incoming Data Flow & Error Branches::

        [ Serial Port / RS-485 Interface ]
                      │
                      ▼
                  _serve()          ────► reads serial stream into byte buffer
                      │
                      ▼
            _extract_next_frame()
                      ├───[ ':' not in buffer ]───────────────► returns None (clears buffer, reads more)
                      ├───[ '\r\n' not in buffer ]────────────► returns None (retains buffer, reads more)
                      └───[ Frame found ]
                                │
                                ▼
           _process_next_frame()
                      │
                      ├───[ frame size < 9 bytes ]────────────► returns (skips frame)
                      ├───[ invalid hex characters ]──────────► returns (skips frame)
                      ├───[ validate_lrc() fails ]────────────► returns (skips frame)
                      ▼
             _get_pdu_class() / decode_request()
                      │
                      ├───[ decoding fails ]──────────────────► responds with IllegalFunction
                      └───[ Happy Path ]──────────────────────► routes, encodes response,
                                                                calculates LRC & writes

    """

    def __init__(
        self,
        port: str,
        handler: ModbusHandler,
        baudrate: int = 19200,
        **serial_kwargs: Any,
    ) -> None:
        """Initialize Async Modbus ASCII Server.

        Args:
            port: Serial port name
            baudrate: Baud rate
            handler: User-defined async handler for processing requests
            serial_kwargs: Additional arguments for `serialx.Serial`

        """
        self.port = port
        self.handler = handler
        self.baudrate = baudrate
        self.serial_kwargs = serial_kwargs
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._running = False
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the server using serialx's async connection."""
        reader, writer = await open_serial_connection(url=self.port, baudrate=self.baudrate, **self.serial_kwargs)
        self._reader = reader
        self._writer = writer
        self._running = True
        self._task = asyncio.create_task(self._serve())
        logger.info("Modbus ASCII Server listening on %s", self.port)

    async def stop(self) -> None:
        """Stop the server."""
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self._writer:
            try:
                self._writer.close()
                with contextlib.suppress(Exception):
                    await self._writer.wait_closed()
            finally:
                self._writer = None
                self._reader = None
                logger.info("Modbus ASCII Server stopped")

    async def serve_forever(self) -> None:
        """Start the server and block until cancelled."""
        await self.start()
        assert self._task is not None
        with contextlib.suppress(asyncio.CancelledError):
            await self._task

    def _extract_next_frame(self, buffer: bytearray) -> tuple[bytes | None, bytearray]:
        """Extract the next complete frame from the buffer if available."""
        while True:
            # Try to find the end of a frame ('\r\n')
            end_idx = buffer.find(b"\r\n")

            if end_idx == -1:
                # No \r\n found yet.
                # Discard any bytes before the last colon since a frame must start with a colon
                last_colon = buffer.rfind(b":")
                if last_colon == -1:
                    # No colon found in the buffer. Everything is garbage.
                    if buffer:
                        log_raw_traffic("recv", bytes(buffer), is_error=True)
                    return None, bytearray()

                if last_colon > 0:
                    log_raw_traffic("recv", bytes(buffer[:last_colon]), is_error=True)
                    buffer = buffer[last_colon:]

                # Check if the colon-aligned buffer has exceeded maximum frame length
                if len(buffer) > 513:
                    # the frame size must be 513 bytes at maximum
                    log_raw_traffic("recv", bytes(buffer), is_error=True)
                    return None, bytearray()
                return None, buffer

            # We found a \r\n. Find the last colon before this \r\n.
            last_colon = buffer.rfind(b":", 0, end_idx)

            if last_colon == -1:
                # No colon before \r\n. Discard everything up to the \r\n.
                log_raw_traffic("recv", bytes(buffer[:end_idx + 2]), is_error=True)
                buffer = buffer[end_idx + 2:]
                continue

            # If there is garbage/noise before the last colon, discard and log it
            if last_colon > 0:
                log_raw_traffic("recv", bytes(buffer[:last_colon]), is_error=True)
                buffer = buffer[last_colon:]
                # Adjust end_idx because slicing the buffer shifted the indices
                end_idx -= last_colon

            frame_len = end_idx + 2
            if frame_len > 515:
                # Frame starting at last_colon is too long. Discard the colon to check the rest.
                log_raw_traffic("recv", bytes(buffer[:1]), is_error=True)
                buffer = buffer[1:]
                continue

            frame = bytes(buffer[:frame_len])
            remaining = buffer[frame_len:]
            return frame, remaining

    async def _process_next_frame(self, frame: bytes) -> Literal["ignored", "success", "error"]:
        """Process a single complete Modbus ASCII frame.

        Returns "ignored", "success", or "error".
        """
        if len(frame) < 9:  # : + unit_id(2) + fc(2) + lrc(2) + \r\n
            logger.warning("ASCII frame too short")
            return "error"

        hex_data = frame[1:-2]
        try:
            bin_data = bytes.fromhex(hex_data.decode("ascii"))
        except ValueError:
            logger.warning("Invalid hex string in ASCII frame")
            return "error"

        if not validate_lrc(bin_data[:-1], bin_data[-1]):
            logger.warning("LRC validation failed")
            return "error"

        unit_id = bin_data[0]
        if not self.handler.supports_unit_id(unit_id):
            return "ignored"

        function_code = bin_data[1]
        pdu_bytes = bin_data[1:-1]  # exclude unit_id and lrc

        is_error = False
        try:
            pdu_class = get_server_pdu_class(pdu_bytes)
            request_pdu = pdu_class.decode_request(pdu_bytes)
        except (ValueError, InvalidRequestError) as e:
            logger.warning("Invalid request: %s", e)
            response_pdu_bytes = bytes([function_code | 0x80, 0x01])
            is_error = True
        else:
            response_pdu_bytes = await handle_modbus_request(unit_id, request_pdu, self.handler)

        if unit_id != 0:
            out_bin = bytearray([unit_id]) + response_pdu_bytes
            lrc = calculate_lrc(bytes(out_bin))
            out_bin.append(lrc)

            out_frame = b":" + out_bin.hex().upper().encode("ascii") + b"\r\n"

            if self._writer:
                self._writer.write(out_frame)
                await self._writer.drain()
                log_raw_traffic("sent", out_frame)
            else:
                logger.warning("No writer available to send ASCII response; dropping frame")
                log_raw_traffic("sent", out_frame, is_error=True)

        return "error" if is_error else "success"

    async def _serve(self) -> None:
        """Read and handle requests in a loop."""
        buffer = bytearray()

        try:
            while self._running and self._reader:
                try:
                    # Read at least 1 byte
                    data = await self._reader.read(1)
                    if not data:
                        continue
                    buffer.extend(data)

                    while True:
                        frame, remaining = self._extract_next_frame(buffer)
                        if frame is None:
                            buffer = remaining
                            break
                        buffer = remaining
                        status = await self._process_next_frame(frame)
                        log_raw_traffic("recv", frame, is_error=(status == "error"), is_ignored=(status == "ignored"))

                except Exception:
                    logger.exception("Error in ASCII server loop")
                    if buffer:
                        log_raw_traffic("recv", bytes(buffer), is_error=True)
                    buffer.clear()
                    await asyncio.sleep(0.1)
        finally:
            if buffer:
                log_raw_traffic("recv", bytes(buffer), is_error=True)
