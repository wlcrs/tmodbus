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

from .handler import ModbusRequestHandler, ModbusService

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "ASCII-Server")


class AsyncAsciiServer:
    """Async Modbus ASCII Server."""

    def __init__(
        self,
        port: str,
        baudrate: int = 19200,
        handler: ModbusService | None = None,
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

                # Check for start character ':'
                try:
                    start_idx = buffer.index(b":")
                except ValueError:
                    buffer.clear()
                    continue

                if start_idx > 0:
                    buffer = buffer[start_idx:]

                # Check for end characters '\r\n'
                try:
                    end_idx = buffer.index(b"\r\n")
                except ValueError:
                    continue

                frame = buffer[: end_idx + 2]
                buffer = buffer[end_idx + 2 :]

                log_raw_traffic("recv", frame)

                if len(frame) < 11:  # : + unit_id(2) + fc(2) + lrc(2) + \r\n
                    continue

                hex_data = frame[1:-2]
                try:
                    bin_data = bytes.fromhex(hex_data.decode("ascii"))
                except ValueError:
                    logger.warning("Invalid hex string in ASCII frame")
                    continue

                if not validate_lrc(bin_data[:-1], bin_data[-1]):
                    logger.warning("LRC validation failed")
                    continue

                unit_id = bin_data[0]
                function_code = bin_data[1]
                pdu_bytes = bin_data[1:-1]  # exclude unit_id and lrc

                try:
                    if is_function_code_for_subfunction_pdu(function_code):
                        if len(pdu_bytes) < 2:
                            msg = "Missing sub-function code"
                            raise InvalidRequestError(msg, request_bytes=pdu_bytes)
                        sub_function_code = pdu_bytes[1]
                        pdu_class = get_subfunction_pdu_class(function_code, sub_function_code)
                    else:
                        pdu_class = get_pdu_class(function_code)  # type: ignore[assignment]

                    if not issubclass(pdu_class, BasePDU):
                        msg = f"PDU class {pdu_class.__name__} does not implement server methods"
                        raise ValueError(msg)

                    request_pdu = pdu_class.decode_request(pdu_bytes)
                except (ValueError, InvalidRequestError) as e:
                    logger.warning("Invalid request: %s", e)
                    response_pdu_bytes = bytes([function_code | 0x80, 0x01])
                else:
                    if self.handler:
                        response_pdu_bytes = await ModbusRequestHandler(unit_id, request_pdu, self.handler)
                    else:
                        response_pdu_bytes = bytes([function_code | 0x80, 0x01])

                out_bin = bytearray([unit_id]) + response_pdu_bytes
                lrc = calculate_lrc(out_bin)
                out_bin.append(lrc)

                out_frame = b":" + out_bin.hex().upper().encode("ascii") + b"\r\n"

                await self._serial.write(out_frame)
                log_raw_traffic("sent", out_frame)

            except Exception as e:
                if self._running:
                    logger.exception("Error in ASCII server loop: %s", e)
                    buffer.clear()
                    await asyncio.sleep(0.1)
