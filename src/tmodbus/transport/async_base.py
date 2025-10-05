"""Async Transport layer base class.

Defines the unified interface that all transport layer implementations must follow.
"""

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Self, TypeVar

from tmodbus.pdu import BaseClientPDU

RT = TypeVar("RT")


class AsyncBaseTransport(ABC):
    """Transport Layer Base Class.

    All transport layer implementations (RTU, TCP, etc.) must inherit from this class
    and implement all abstract methods. This design completely encapsulates complexities
    such as CRC verification and MBAP header processing within the transport layer,
    providing a unified and concise interface for clients.
    """

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
