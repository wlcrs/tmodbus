"""ModbusLink Asynchronous Client Implementation.

Provides user-friendly asynchronous Modbus client API.
"""

import logging
from types import TracebackType
from typing import Literal, Self, TypeVar

from tmodbus.pdu import (
    BaseClientPDU,
    ReadCoilsPDU,
    ReadDeviceIdentificationPDU,
    ReadDiscreteInputsPDU,
    ReadHoldingRegistersPDU,
    ReadInputRegistersPDU,
    WriteMultipleCoilsPDU,
    WriteMultipleRegistersPDU,
    WriteSingleCoilPDU,
    WriteSingleRegisterPDU,
)
from tmodbus.pdu.holding_registers_struct import HoldingRegisterReadMixin, HoldingRegisterWriteMixin
from tmodbus.transport.async_base import AsyncBaseTransport

logger = logging.getLogger(__name__)

RT = TypeVar("RT")


class AsyncModbusClient(HoldingRegisterReadMixin, HoldingRegisterWriteMixin):
    """Asynchronous Modbus Client.

    Provides an user-friendly asynchronous Modbus interface to a single Modbus device.
    All methods use Python native data types (int, float, str, list, etc.),

    If you want to query another device on the same connection, use the `for_unit_id` method.

    This class is agnostic to the transport layer: just pass the desired transport instance.

    Example:
        >>> import asyncio
        >>> from tmodbus import AsyncModbusClient, AsyncTcpTransport
        >>> async def main():
        ...     transport = AsyncTcpTransport('localhost', 502)
        ...     client = AsyncModbusClient(transport, unit_id=1)
        ...     async with client:
        ...         print("Contents of register 0:", await client.read_holding_registers(0, 1))
        ...
        >>> asyncio.run(main())

    """

    def __init__(
        self,
        transport: AsyncBaseTransport,
        *,
        unit_id: int,
        word_order: Literal["big", "little"] = "big",
    ) -> None:
        """Initialize Async Modbus Client.

        Args:
            transport: Async transport layer instance (AsyncTcpTransport, etc.)
            unit_id: Unit ID of the Modbus device
            word_order: Word order for multi-register values ('big' or 'little').

        """
        HoldingRegisterReadMixin.__init__(self, word_order=word_order)
        HoldingRegisterWriteMixin.__init__(self, word_order=word_order)
        self.transport = transport

        if not (0 <= unit_id <= 255):
            msg = "Unit ID must be in range 0-255"
            raise ValueError(msg)

        self.unit_id = unit_id

    async def connect(self) -> None:
        """Connect to the server."""
        await self.transport.open()

    @property
    def connected(self) -> bool:
        """Report if the client is connected to the server."""
        return self.transport.is_open()

    async def disconnect(self) -> None:
        """Close the server connection."""
        await self.transport.close()

    async def execute(self, pdu: BaseClientPDU[RT]) -> RT:
        """Execute PDU Request.

        Args:
            pdu: Modbus PDU instance
        Returns:
            Response PDU bytes

        Raises:
            InvalidResponseError: If response is invalid or does not match request

        """
        return await self.transport.send_and_receive(self.unit_id, pdu)

    async def read_coils(
        self,
        start_address: int,
        quantity: int,
    ) -> list[bool]:
        """Read Coil Status (Function Code 0x01).

        Args:
            start_address:  Starting address
            quantity:  Quantity to read (1-2000)

        Returns:
            List of coil status, True for ON, False for OFF

        Raises:
            InvalidResponseError: If response is invalid or does not match request

        Example:
            >>> coils = await client.read_coils(1, 0, 8)
            [True, False, True, False, False, False, True, False]

        """
        return await self.execute(ReadCoilsPDU(start_address, quantity))

    async def read_discrete_inputs(
        self,
        start_address: int,
        quantity: int,
    ) -> list[bool]:
        """Read Discrete Inputs (Function Code 0x02).

        Args:
            start_address:  Starting address
            quantity:  Quantity to read (1-2000)

        Returns:
            List of coil status, True for ON, False for OFF

        Example:
            >>> coils = await client.read_coils(1, 0, 8)
            [True, False, True, False, False, False, True, False]

        """
        return await self.execute(ReadDiscreteInputsPDU(start_address, quantity))

    async def read_holding_registers(
        self,
        start_address: int,
        quantity: int,
    ) -> list[int]:
        """Read Holding Registers (Function Code 0x03).

        Args:
            start_address: Starting address
            quantity: Quantity to read (1-125)


        Returns:
            List of register values, each value is a 16-bit unsigned integer (0-65535)

        Example:
            >>> registers = await client.read_holding_registers(0, 4)  # Read holding registers 0, 1, 2, 3
            [1234, 5678, 9012, 3456]

        """
        return await self.execute(ReadHoldingRegistersPDU(start_address, quantity))

    async def read_input_registers(
        self,
        start_address: int,
        quantity: int,
    ) -> list[int]:
        """Read Input Registers (Function Code 0x04).

        Args:
            start_address: Starting address
            quantity: Quantity to read (1-125)


        Returns:
            List of register values, each value is a 16-bit unsigned integer (0-65535)

        Example:
            >>> registers = await client.read_input_registers(0, 4) # Read input registers 0, 1, 2, 3
            [1234, 5678, 9012, 3456]

        """
        return await self.execute(ReadInputRegistersPDU(start_address, quantity))

    async def write_single_coil(
        self,
        address: int,
        value: bool,  # noqa: FBT001
    ) -> int:
        """Write Single Coil (Function Code 0x05).

        Args:
            address: Coil address
            value: Coil value (True for ON, False for OFF)


        Returns:
            The value that was written

        Example:
            >>> await client.write_single_coil(0, True)  # Write ON to coil 0

        """
        return await self.execute(WriteSingleCoilPDU(address, value))

    async def write_single_register(
        self,
        address: int,
        value: int,
    ) -> int:
        """Write Single Register (Function Code 0x06).

        Args:
            address: Register address
            value: Register value (0-65535)

        Returns:
            the value that was written

        Example:
            >>> await client.write_single_register(0, 1234)  # Write 1234 to register 0

        """
        return await self.execute(WriteSingleRegisterPDU(address, value))

    async def write_multiple_coils(
        self,
        start_address: int,
        values: list[bool],
    ) -> int:
        """Write Multiple Coils (Function Code 0x0F).

        Args:
            start_address: Starting address
            values: List of coil values, True for ON, False for OFF


        Returns:
            The number of coils that have been written to.

        Example:
            >>> await client.write_multiple_coils(0, [True, False, True, False])

        """
        return await self.execute(WriteMultipleCoilsPDU(start_address, values))

    async def write_multiple_registers(
        self,
        start_address: int,
        values: list[int],
    ) -> int:
        """Write Multiple Registers (Function Code 0x10).

        Args:
            start_address: Starting address
            values: List of register values, each value 0-65535


        Returns:
            The number of registers that have been written to.

        Example:
            >>> await client.write_multiple_registers(0, [1234, 5678, 9012])

        """
        return await self.execute(WriteMultipleRegistersPDU(start_address, values))

    async def read_device_identification(
        self,
        device_code: Literal[0x01, 0x02, 0x03, 0x04],
        object_id: int,
    ) -> dict[int, bytes]:
        """Read Device Identification (Function Code 0x2B/0x0E).

        Args:
            device_code: Device code (0x01 for Basic, 0x02 for Regular, 0x03 for Extended, 0x04 for Specific)
            object_id: Object ID to start reading from (0x00 to 0xFF)


        Returns:
            A dictionary mapping object IDs to their corresponding string values.

        Example:
            >>> device_info = await client.read_device_identification(1, 0)
            {0: 'VendorName', 1: 'ProductCode', ...}

        """
        result: dict[int, bytes] = {}
        more = True
        number_of_objects: int | None = None
        while more:
            response = await self.execute(ReadDeviceIdentificationPDU(device_code, object_id))
            result.update(response.objects)
            more = response.more
            object_id = response.next_object_id

            if number_of_objects is None:
                number_of_objects = response.number_of_objects
            elif number_of_objects != response.number_of_objects:
                logger.warning(
                    "Number of objects changed between requests: was %d, now %d",
                    number_of_objects,
                    response.number_of_objects,
                )

        return result

    async def __aenter__(self) -> Self:
        """Async context manager entry."""
        await self.transport.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Async context manager exit."""
        await self.transport.close()

    def for_unit_id(self, unit_id: int) -> "AsyncModbusClient":
        """Create a new client instance for a different unit ID, but using the same connection.

        Args:
            unit_id: The unit ID for the new client instance.

        Returns:
            A new instance of AsyncModbusClient configured for the specified unit ID.

        """
        return AsyncModbusClient(self.transport, unit_id=unit_id, word_order=self.word_order)
