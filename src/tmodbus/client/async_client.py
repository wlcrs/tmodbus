"""ModbusLink Asynchronous Client Implementation.

Provides user-friendly asynchronous Modbus client API.
"""

from types import TracebackType
from typing import Self, TypeVar

from tmodbus.pdu import (
    BaseModbusPDU,
    ReadCoilsPDU,
    ReadDiscreteInputsPDU,
    ReadHoldingRegistersPDU,
    ReadInputRegistersPDU,
    WriteMultipleCoilsPDU,
    WriteMultipleRegistersPDU,
    WriteSingleCoilPDU,
    WriteSingleRegisterPDU,
)
from tmodbus.transport.async_base import AsyncBaseTransport

RT = TypeVar("RT")


class AsyncModbusClient:
    """Asynchronous Modbus Client.

    Provides a concise, user-friendly asynchronous Modbus operation interface. Receives
    async transport layer instances through dependency injection, supporting async
    transport methods such as async TCP.

    All methods use Python native data types (int, list, etc.),
    completely encapsulating underlying byte operations, and support callback mechanisms.
    """

    def __init__(self, transport: AsyncBaseTransport) -> None:
        """Initialize Async Modbus Client.

        Args:
            transport: Async transport layer instance (AsyncTcpTransport, etc.)

        """
        self.transport = transport

    async def execute(self, pdu: BaseModbusPDU[RT], *, unit_id: int) -> RT:
        """Execute PDU Request.

        Args:
            pdu: Modbus PDU instance
            unit_id: Unit ID of the Modbus device

        Returns:
            Response PDU bytes

        Raises:
            InvalidResponseError: If response is invalid or does not match request

        """
        return await self.transport.send_and_receive(unit_id, pdu)

    async def read_coils(
        self,
        start_address: int,
        quantity: int,
        *,
        unit_id: int,
    ) -> list[bool]:
        """Read Coil Status (Function Code 0x01).

        Args:
            unit_id: Unit ID
            start_address:  Starting address
            quantity:  Quantity to read (1-2000)

        Returns:
            List of coil status, True for ON, False for OFF

        Example:
            >>> coils = await client.read_coils(1, 0, 8)
            [True, False, True, False, False, False, True, False]

        """
        return await self.execute(ReadCoilsPDU(start_address, quantity), unit_id=unit_id)

    async def read_discrete_inputs(
        self,
        start_address: int,
        quantity: int,
        *,
        unit_id: int,
    ) -> list[bool]:
        """Read Discrete Inputs (Function Code 0x02).

        Args:
            unit_id: Unit ID
            start_address:  Starting address
            quantity:  Quantity to read (1-2000)

        Returns:
            List of coil status, True for ON, False for OFF

        Example:
            >>> coils = await client.read_coils(1, 0, 8)
            [True, False, True, False, False, False, True, False]

        """
        return await self.execute(ReadDiscreteInputsPDU(start_address, quantity), unit_id=unit_id)

    async def read_holding_registers(
        self,
        start_address: int,
        quantity: int,
        *,
        unit_id: int,
    ) -> list[int]:
        """Read Holding Registers (Function Code 0x03).

        Args:
            start_address: Starting address
            quantity: Quantity to read (1-125)
            unit_id: Unit ID

        Returns:
            List of register values, each value is a 16-bit unsigned integer (0-65535)

        Example:
            >>> registers = await client.read_holding_registers(0, 4, unit_id=1)  # Read holding registers 0, 1, 2, 3
            [1234, 5678, 9012, 3456]

        """
        return await self.execute(ReadHoldingRegistersPDU(start_address, quantity), unit_id=unit_id)

    async def read_input_registers(
        self,
        start_address: int,
        quantity: int,
        *,
        unit_id: int,
    ) -> list[int]:
        """Read Input Registers (Function Code 0x04).

        Args:
            start_address: Starting address
            quantity: Quantity to read (1-125)
            unit_id: Unit ID

        Returns:
            List of register values, each value is a 16-bit unsigned integer (0-65535)

        Example:
            >>> registers = await client.read_input_registers(0, 4, unit_id=1) # Read input registers 0, 1, 2, 3
            [1234, 5678, 9012, 3456]

        """
        return await self.execute(ReadInputRegistersPDU(start_address, quantity), unit_id=unit_id)

    async def write_single_coil(
        self,
        address: int,
        value: bool,  # noqa: FBT001
        *,
        unit_id: int,
    ) -> None:
        """Write Single Coil (Function Code 0x05).

        Args:
            address: Coil address
            value: Coil value (True for ON, False for OFF)
            unit_id: Unit ID

        Example:
            >>> await client.write_single_coil(0, True, unit_id=1)  # Write ON to coil 0

        """
        return await self.execute(WriteSingleCoilPDU(address, value), unit_id=unit_id)

    async def write_single_register(
        self,
        address: int,
        value: int,
        *,
        unit_id: int,
    ) -> None:
        """Write Single Register (Function Code 0x06).

        Args:
            address: Register address
            value: Register value (0-65535)

        Example:
            >>> await client.write_single_register(0, 1234, unit_id=1) # Write 1234 to register 0

        """
        return await self.execute(WriteSingleRegisterPDU(address, value), unit_id=unit_id)

    async def write_multiple_coils(
        self,
        start_address: int,
        values: list[bool],
        *,
        unit_id: int,
    ) -> None:
        """Write Multiple Coils (Function Code 0x0F).

        Args:
            start_address: Starting address
            values: List of coil values, True for ON, False for OFF
            unit_id: Unit ID

        Example:
            >>> await client.write_multiple_coils(0, [True, False, True, False], unit_id=1)

        """
        return await self.execute(WriteMultipleCoilsPDU(start_address, values), unit_id=unit_id)

    async def write_multiple_registers(
        self,
        start_address: int,
        values: list[int],
        *,
        unit_id: int,
    ) -> None:
        """Write Multiple Registers (Function Code 0x10).

        Args:
            start_address: Starting address
            values: List of register values, each value 0-65535
            unit_id: Unit ID


        Example:
            >>> await client.write_multiple_registers(0, [1234, 5678, 9012], unit_id=1)

        """
        return await self.execute(WriteMultipleRegistersPDU(start_address, values), unit_id=unit_id)

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
