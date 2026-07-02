"""Async Transport layer base class.

Defines the unified interface that all transport layer implementations must follow.
"""

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from types import TracebackType
from typing import Self, TypeVar

from tmodbus.pdu import BaseClientPDU

RT = TypeVar("RT")

logger = logging.getLogger(__name__)


class AsyncBaseTransport(ABC):
    """Transport Layer Base Class.

    All transport layer implementations (RTU, TCP, etc.) must inherit from this class
    and implement all abstract methods. This design completely encapsulates complexities
    such as CRC verification and MBAP header processing within the transport layer,
    providing a unified and concise interface for clients.
    """

    #: Optional callback invoked the moment the connection is lost.
    #:
    #: It is called with the exception that caused the loss (or ``None`` when the
    #: connection was closed cleanly, e.g. by the remote host or via :meth:`close`).
    #: This fires straight from the underlying protocol's ``connection_lost``, so it
    #: is the earliest possible notification that the socket dropped, independent of
    #: whether any request is in flight.
    on_connection_lost: Callable[[Exception | None], None] | None = None

    def _notify_connection_lost(self, exc: Exception | None) -> None:
        """Invoke the ``on_connection_lost`` callback, swallowing any error it raises.

        A misbehaving user callback must never break the transport teardown that runs
        inside the event loop's ``connection_lost`` handling.
        """
        callback = self.on_connection_lost
        if callback is None:
            return
        try:
            callback(exc)
        except Exception:
            logger.exception("Unhandled error in on_connection_lost callback")

    @abstractmethod
    async def open(self) -> None:
        """Open Transport Connection.

        Establishes connection with Modbus device. For serial port, opens the port;
        for TCP, establishes socket connection.

        Raises:
            ConnectionError: When connection cannot be established

        """

    @abstractmethod
    async def close(self) -> None:
        """Close Transport Connection.

        Closes connection with Modbus device and releases related resources.
        """

    @abstractmethod
    def is_open(self) -> bool:
        """Check Connection Status.

        Returns:
            True if connection is established and available, False otherwise

        """

    @abstractmethod
    async def send_and_receive(self, unit_id: int, pdu: BaseClientPDU[RT]) -> RT:
        """Send PDU and Receive Response.

        This is the core method of the transport layer. It receives pure PDU (Protocol Data Unit),
        is responsible for adding necessary transport layer information (such as RTU address and CRC,
        or TCP MBAP header), sends requests, receives responses, verifies response integrity,
        and then returns the PDU part of the response.

        Args:
            unit_id: Slave address/unit identifier
            pdu: Protocol Data Unit, contains function code and data, excludes address and checksum

        Returns:
            PDU part of response with transport layer information removed

        Raises:
            ConnectionError: Connection error
            TimeoutError:  Operation timeout
            CRCError: CRC verification failed (RTU only)
            LRCError: LRC verification failed (ASCII only)
            InvalidResponseError: Invalid response format

        """

    async def __aenter__(self) -> Self:
        """Async Context Manager Entry."""
        await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Async Context Manager Exit."""
        await self.close()
