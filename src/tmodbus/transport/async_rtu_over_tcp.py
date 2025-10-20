"""Async RTU over TCP Transport Layer Implementation.

Implements Modbus RTU over TCP protocol transport, which uses:
- TCP/IP for the network layer (like standard Modbus TCP)
- RTU framing with CRC-16 for the data layer (instead of MBAP header)

This is useful for serial-to-Ethernet converters that encapsulate RTU frames
in TCP packets without converting to Modbus TCP format.
"""

import asyncio
import logging
from functools import partial
from typing import Any, TypeVar

from tmodbus.exceptions import (
    ModbusConnectionError,
)
from tmodbus.pdu import BaseClientPDU
from tmodbus.utils.raw_traffic_logger import log_raw_traffic as base_log_raw_traffic

from .async_base import AsyncBaseTransport
from .async_rtu import ModbusRtuProtocol

RT = TypeVar("RT")

logger = logging.getLogger(__name__)
log_raw_traffic = partial(base_log_raw_traffic, "RTU/TCP")

MAX_RTU_FRAME_SIZE = 256  # Maximum RTU frame size in bytes
MIN_RTU_RESPONSE_LENGTH = 4  # Minimal response: address + function code + CRC (2 bytes)


class AsyncRtuOverTcpTransport(AsyncBaseTransport):
    """Async Modbus RTU over TCP Transport Layer Implementation.

    Handles async Modbus RTU over TCP communication, combining:
    - TCP connection management (like AsyncTcpTransport)
    - RTU framing with CRC-16 validation (like AsyncRtuTransport)

    This transport is used for serial-to-Ethernet converters that forward
    RTU frames over TCP without converting them to Modbus TCP format.
    """

    _transport: asyncio.Transport | None = None
    _protocol: "ModbusRtuProtocol | None" = None

    def __init__(
        self,
        host: str,
        port: int = 502,
        *,
        timeout: float = 10.0,
        connect_timeout: float = 10.0,
        **connection_kwargs: Any,
    ) -> None:
        """Initialize async RTU over TCP transport layer.

        Args:
            host: Target host IP address or domain name
            port: Target port, default 502 (Modbus TCP standard port)
            timeout: Timeout in seconds for read/write operations, default 10.0s
            connect_timeout: Timeout for establishing connection, default 10.0s
            connection_kwargs: Additional connection parameters passed to `asyncio.open_connection`

        Raises:
            ValueError: When parameters are invalid

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
        """Establish TCP connection."""
        loop = asyncio.get_running_loop()
        if self.is_open():
            logger.debug("Async RTU/TCP connection already open: %s:%d", self.host, self.port)
            return

        try:
            self._transport, self._protocol = await loop.create_connection(
                lambda: ModbusRtuProtocol(on_connection_lost=self._on_connection_lost, timeout=self.timeout),
                host=self.host,
                port=self.port,
                **self.connection_kwargs,
            )

            logger.info("Async RTU/TCP connection established: %s:%d", self.host, self.port)
        except TimeoutError:
            logger.warning("Async RTU/TCP connection timeout: %s:%d", self.host, self.port, exc_info=True)
            raise
        except Exception as e:
            logger.exception("Async RTU/TCP connection error: %s:%d", self.host, self.port)
            raise ModbusConnectionError from e

    async def close(self) -> None:
        """Close RTU/TCP connection."""
        if not self._transport or self._transport.is_closing():
            logger.debug("Async RTU/TCP connection already closed: %s:%d", self.host, self.port)
            return

        try:
            self._transport.close()
            logger.info("Async RTU/TCP connection closed: %s:%d", self.host, self.port)
        except Exception as e:  # noqa: BLE001
            logger.debug("Error during async connection close: %s", e)

    def is_open(self) -> bool:
        """Check RTU/TCP connection status."""
        return self._transport is not None and not self._transport.is_closing()

    def _on_connection_lost(self, exc: Exception | None) -> None:
        if exc:
            logger.error("Async RTU/TCP connection lost due to error: %s", exc)
        else:
            logger.info("Async RTU/TCP connection closed by remote host.")

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
