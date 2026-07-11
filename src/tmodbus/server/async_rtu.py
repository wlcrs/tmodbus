"""Async Modbus RTU Server."""

import asyncio
import contextlib
import logging
from functools import partial
from typing import Any

from serialx import Serial

from tmodbus.exceptions import InvalidRequestError
from tmodbus.pdu import BasePDU, get_pdu_class, get_subfunction_pdu_class, is_function_code_for_subfunction_pdu
from tmodbus.utils.crc import calculate_crc16, validate_crc16
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .handler import ModbusRequestHandler, ModbusService

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "RTU-Server")

MAX_RTU_FRAME_SIZE = 256


class AsyncRtuServer:
    """Async Modbus RTU Server."""

    def __init__(
        self,
        port: str,
        baudrate: int = 19200,
        handler: ModbusService | None = None,
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
        self.baudrate = baudrate
        self.handler = handler
        self.serial_kwargs = serial_kwargs
        self._serial: Serial | None = None
        self._running = False
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the server."""
        if self.handler is None:
            msg = "No handler specified for Modbus Server"
            raise ValueError(msg)

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

                # Check if we have enough to determine length
                if len(buffer) < 2:
                    continue

                unit_id = buffer[0]
                function_code = buffer[1]

                try:
                    if is_function_code_for_subfunction_pdu(function_code):
                        if len(buffer) < 3:
                            continue
                        sub_function_code = buffer[2]
                        pdu_class = get_subfunction_pdu_class(function_code, sub_function_code)
                    else:
                        pdu_class = get_pdu_class(function_code)  # type: ignore[assignment]

                    if not issubclass(pdu_class, BasePDU):
                        msg = f"PDU class {pdu_class.__name__} does not implement server methods"
                        raise ValueError(msg)

                except ValueError:
                    logger.warning("Unsupported function code %02X, clearing buffer", function_code)
                    buffer.clear()
                    continue

                # get expected length of request data part
                if len(buffer) > 2:
                    expected_data_len = pdu_class.get_expected_request_data_length(buffer[2:])
                else:
                    # we don't have enough data to get length
                    continue

                expected_total_len = 1 + 1 + expected_data_len + 2  # unit_id + fc + data + crc

                if expected_total_len > MAX_RTU_FRAME_SIZE:
                    logger.warning("Expected frame size too large: %d", expected_total_len)
                    buffer.clear()
                    continue

                if len(buffer) < expected_total_len:
                    # Keep reading
                    continue

                # We have a full frame
                frame = buffer[:expected_total_len]
                buffer = buffer[expected_total_len:]

                log_raw_traffic("recv", frame)

                # Validate CRC
                if not validate_crc16(frame):
                    logger.warning("CRC validation failed")
                    continue

                pdu_bytes = frame[1:-2]
                try:
                    request_pdu = pdu_class.decode_request(pdu_bytes)
                except InvalidRequestError as e:
                    logger.warning("Invalid request: %s", e)
                    # Respond with illegal function
                    response_pdu_bytes = bytes([function_code | 0x80, 0x01])
                else:
                    if self.handler:
                        response_pdu_bytes = await ModbusRequestHandler(unit_id, request_pdu, self.handler)
                    else:
                        response_pdu_bytes = bytes([function_code | 0x80, 0x01])

                out_frame = bytearray([unit_id]) + response_pdu_bytes
                crc = calculate_crc16(out_frame)
                out_frame.extend(crc)

                await self._serial.write(out_frame)
                log_raw_traffic("sent", out_frame)

            except Exception as e:
                if self._running:
                    logger.exception("Error in RTU server loop: %s", e)
                    # Simple recovery mechanism
                    buffer.clear()
                    await asyncio.sleep(0.1)
