"""Async Modbus ASCII Server."""

import asyncio
import contextlib
import logging
from functools import partial
from typing import Any

from serialx import Serial

from tmodbus.exceptions import InvalidRequestError
from tmodbus.pdu import BasePDU, get_pdu_class, get_subfunction_pdu_class, is_function_code_for_subfunction_pdu
from tmodbus.utils.lrc import calculate_lrc, validate_lrc
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .handler import ModbusHandler, handle_modbus_request, is_server_pdu_class

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "ASCII-Server")


class AsyncAsciiServer:
    r"""Async Modbus ASCII Server.

    Incoming Data Flow & Error Branches:
    ```
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
    ```
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
        self._serial: Serial | None = None
        self._running = False
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the server."""
        self._serial = Serial(self.port, baudrate=self.baudrate, **self.serial_kwargs)
        self._serial.open()
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

        if self._serial:
            self._serial.close()
            self._serial = None
            logger.info("Modbus ASCII Server stopped")

    async def serve_forever(self) -> None:
        """Start the server and block until cancelled."""
        await self.start()
        if self._task:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    def _get_pdu_class(self, function_code: int, pdu_bytes: bytes) -> type[BasePDU[Any]]:
        """Get the PDU class for the given function code."""
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

        return raw_pdu_class

    def _extract_next_frame(self, buffer: bytearray) -> tuple[bytes | None, bytearray]:
        """Extract the next complete frame from the buffer if available."""
        try:
            start_idx = buffer.index(b":")
        except ValueError:
            return None, bytearray()

        if start_idx > 0:
            buffer = buffer[start_idx:]

        try:
            end_idx = buffer.index(b"\r\n")
        except ValueError:
            return None, buffer

        frame = bytes(buffer[: end_idx + 2])
        remaining = buffer[end_idx + 2 :]
        return frame, remaining

    async def _process_next_frame(self, frame: bytes) -> None:
        """Process a single complete Modbus ASCII frame."""
        if len(frame) < 9:  # : + unit_id(2) + fc(2) + lrc(2) + \r\n
            return

        hex_data = frame[1:-2]
        try:
            bin_data = bytes.fromhex(hex_data.decode("ascii"))
        except ValueError:
            logger.warning("Invalid hex string in ASCII frame")
            return

        if not validate_lrc(bin_data[:-1], bin_data[-1]):
            logger.warning("LRC validation failed")
            return

        unit_id = bin_data[0]
        function_code = bin_data[1]
        pdu_bytes = bin_data[1:-1]  # exclude unit_id and lrc

        try:
            pdu_class = self._get_pdu_class(function_code, pdu_bytes)
            request_pdu = pdu_class.decode_request(pdu_bytes)
        except (ValueError, InvalidRequestError) as e:
            logger.warning("Invalid request: %s", e)
            response_pdu_bytes = bytes([function_code | 0x80, 0x01])
        else:
            if self.handler:
                response_pdu_bytes = await handle_modbus_request(unit_id, request_pdu, self.handler)
            else:
                response_pdu_bytes = bytes([function_code | 0x80, 0x01])

        out_bin = bytearray([unit_id]) + response_pdu_bytes
        lrc = calculate_lrc(out_bin)
        out_bin.append(lrc)

        out_frame = b":" + out_bin.hex().upper().encode("ascii") + b"\r\n"

        if self._serial:
            await self._serial.write(out_frame)
            log_raw_traffic("sent", out_frame)

    async def _serve(self) -> None:
        """Read and handle requests in a loop."""
        buffer = bytearray()

        while self._running and self._serial:
            try:
                # Read at least 1 byte
                data = await self._serial.read()
                if not data:
                    continue
                buffer.extend(data)

                if len(buffer) > 513:
                    logger.warning("ASCII buffer exceeded maximum frame size, clearing")
                    buffer.clear()
                    continue

                while True:
                    frame, remaining = self._extract_next_frame(buffer)
                    if frame is None:
                        buffer = remaining
                        break
                    buffer = remaining
                    log_raw_traffic("recv", frame)
                    await self._process_next_frame(frame)

            except Exception:
                if self._running:
                    logger.exception("Error in ASCII server loop")
                    buffer.clear()
                    await asyncio.sleep(0.1)
