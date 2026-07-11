"""Async Modbus RTU Server."""

import asyncio
import contextlib
import logging
from functools import partial
from typing import Any, Literal

from serialx import Serial

from tmodbus.exceptions import InvalidRequestError
from tmodbus.pdu import BasePDU, get_pdu_class, get_subfunction_pdu_class, is_function_code_for_subfunction_pdu
from tmodbus.utils.crc import calculate_crc16, validate_crc16
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .handler import ModbusHandler, handle_modbus_request, is_server_pdu_class

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "RTU-Server")

MAX_RTU_FRAME_SIZE = 256


class AsyncRtuServer:
    """Async Modbus RTU Server.

    Incoming Data Flow & Error Branches:
    ```
    [ Serial Port / RS-485 Interface ]
                  │
                  ▼
              _serve()          ────► reads serial stream into byte buffer
                  │
                  ▼
       _process_next_frame()
                  │
                  ├──► _parse_frame_length()
                  │         ├───[ buffer < 2 bytes ]──────► returns "need_data" (reads more)
                  │         ├───[ unsupported function ]──► returns "processed" (clears buffer, continues loop)
                  │         ├───[ expected size > 256 ]───► returns "processed" (clears buffer, continues loop)
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
        port: str,
        handler: ModbusHandler,
        baudrate: int = 19200,
        **serial_kwargs: Any,
    ) -> None:
        """Initialize Async Modbus RTU Server.

        Args:
            port: Serial port name (e.g., /dev/ttyUSB0 or COM1)
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
        logger.info("Modbus RTU Server listening on %s", self.port)

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
            logger.info("Modbus RTU Server stopped")

    async def serve_forever(self) -> None:
        """Start the server and block until cancelled."""
        await self.start()
        if self._task:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

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

    async def _handle_frame(self, frame: bytes) -> None:
        """Handle a validated frame."""
        unit_id = frame[0]
        function_code = frame[1]
        pdu_bytes = frame[1:-2]

        pdu_class = self._get_pdu_class(function_code, bytearray(frame))
        assert pdu_class is not None

        try:
            request_pdu = pdu_class.decode_request(pdu_bytes)
        except InvalidRequestError as e:
            logger.warning("Invalid request: %s", e)
            response_pdu_bytes = bytes([function_code | 0x80, 0x01])
        else:
            if self.handler:
                response_pdu_bytes = await handle_modbus_request(unit_id, request_pdu, self.handler)
            else:
                response_pdu_bytes = bytes([function_code | 0x80, 0x01])

        out_frame = bytearray([unit_id]) + response_pdu_bytes
        crc = calculate_crc16(out_frame)
        out_frame.extend(crc)

        if self._serial:
            await self._serial.write(out_frame)
            log_raw_traffic("sent", out_frame)

    async def _process_next_frame(self, buffer: bytearray) -> Literal["need_data", "processed"]:
        """Process the next frame in the buffer if possible.

        Returns:
            "need_data": wait for more bytes
            "processed": successfully processed (or skipped a bad frame)

        """
        try:
            expected_total_len = self._parse_frame_length(buffer)
            if expected_total_len is None:
                return "need_data"
        except ValueError as e:
            logger.warning("%s, clearing buffer", e)
            buffer.clear()
            return "processed"

        if len(buffer) < expected_total_len:
            return "need_data"

        # We have a full frame
        frame = buffer[:expected_total_len]
        del buffer[:expected_total_len]

        log_raw_traffic("recv", frame)

        # Validate CRC
        if not validate_crc16(frame):
            logger.warning("CRC validation failed")
            return "processed"

        await self._handle_frame(frame)
        return "processed"

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

                while True:
                    status = await self._process_next_frame(buffer)
                    if status == "need_data":
                        break

            except Exception:
                if self._running:
                    logger.exception("Error in RTU server loop")
                    # Simple recovery mechanism
                    buffer.clear()
                    await asyncio.sleep(0.1)
