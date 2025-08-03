"""Holding Registers utilities."""

import struct
from typing import Any, Protocol, TypeVar

from .base import BaseModbusPDU
from .holding_registers import RawReadHoldingRegistersPDU, RawWriteMultipleRegistersPDU

RT = TypeVar("RT")


class SupportsExecuteAsync(Protocol):
    """Protocol for classes that support the execute method."""

    async def execute(self, pdu: BaseModbusPDU[RT], *, unit_id: int) -> RT:
        """Send the PDU and return the response."""
        ...


class HoldingRegisterReadMixin(SupportsExecuteAsync):
    """Mixin for holding register read operations."""

    async def read_struct_format[RT](
        self,
        start_address: int,
        *,
        format_struct: struct.Struct,
        unit_id: int,
    ) -> tuple[Any, ...]:
        """Read holding registers and decode them using the provided struct format.

        Args:
            struct_format: Struct format to decode the response
            start_address: Starting address of the registers to read
            unit_id: Unit ID

        Returns:
            Decoded response data using the provided struct format

        """
        response_bytes = await self.execute(
            RawReadHoldingRegistersPDU(
                start_address,
                quantity=format_struct.size // 2,
            ),
            unit_id=unit_id,
        )
        return format_struct.unpack_from(response_bytes)

    async def read_simple_struct_format(
        self,
        start_address: int,
        *,
        format_struct: struct.Struct,
        unit_id: int,
    ) -> Any:
        """Read holding registers and decode them as a single value using the provided struct format.

        Args:
            struct_format: Struct format to decode the response
            start_address: Starting address of the registers to read
            unit_id: Unit ID

        Returns:
            Decoded response data as a single value

        """
        return (await self.read_struct_format(start_address, format_struct=format_struct, unit_id=unit_id))[0]

    async def read_uint16(
        self,
        start_address: int,
        *,
        unit_id: int,
    ) -> int:
        """Read holding registers and decode them as an unsigned 16-bit integer.

        Args:
            start_address: Starting address of the registers to read.
            unit_id: Unit ID.

        Returns:
            Decoded unsigned 16-bit integer.

        """
        return await self.read_simple_struct_format(
            start_address,
            format_struct=struct.Struct(">H"),
            unit_id=unit_id,
        )

    async def read_uint32(
        self,
        start_address: int,
        *,
        unit_id: int,
    ) -> int:
        """Read holding registers and decode them as an unsigned 32-bit integer.

        Args:
            start_address: Starting address of the registers to read.
            unit_id: Unit ID.

        Returns:
            Decoded unsigned 32-bit integer.

        """
        return await self.read_simple_struct_format(
            start_address,
            format_struct=struct.Struct(">I"),
            unit_id=unit_id,
        )

    async def read_uint64(
        self,
        start_address: int,
        *,
        unit_id: int,
    ) -> int:
        """Read holding registers and decode them as an unsigned 64-bit integer.

        Args:
            start_address: Starting address of the registers to read.
            unit_id: Unit ID.

        Returns:
            Decoded unsigned 64-bit integer.

        """
        return await self.read_simple_struct_format(
            start_address,
            format_struct=struct.Struct(">Q"),
            unit_id=unit_id,
        )

    async def read_int16(
        self,
        start_address: int,
        *,
        unit_id: int,
    ) -> int:
        """Read holding registers and decode them as a signed 16-bit integer.

        Args:
            start_address: Starting address of the registers to read.
            unit_id: Unit ID.

        Returns:
            Decoded signed 16-bit integer.

        """
        return await self.read_simple_struct_format(
            start_address,
            format_struct=struct.Struct(">h"),
            unit_id=unit_id,
        )

    async def read_int32(
        self,
        start_address: int,
        *,
        unit_id: int,
    ) -> int:
        """Read holding registers and decode them as a signed 32-bit integer.

        Args:
            start_address: Starting address of the registers to read.
            unit_id: Unit ID.

        Returns:
            Decoded signed 32-bit integer.

        """
        return await self.read_simple_struct_format(
            start_address,
            format_struct=struct.Struct(">i"),
            unit_id=unit_id,
        )

    async def read_int64(
        self,
        start_address: int,
        *,
        unit_id: int,
    ) -> int:
        """Read holding registers and decode them as a signed 64-bit integer.

        Args:
            start_address: Starting address of the registers to read.
            unit_id: Unit ID.

        Returns:
            Decoded signed 64-bit integer.

        """
        return await self.read_simple_struct_format(
            start_address,
            format_struct=struct.Struct(">q"),
            unit_id=unit_id,
        )

    async def read_float(
        self,
        start_address: int,
        *,
        unit_id: int,
    ) -> float:
        """Read holding registers and decode them as a float.

        Args:
            start_address: Starting address of the registers to read.
            unit_id: Unit ID.

        Returns:
            Decoded float value.

        """
        return await self.read_simple_struct_format(
            start_address,
            format_struct=struct.Struct(">f"),
            unit_id=unit_id,
        )

    async def read_string(
        self,
        start_address: int,
        *,
        number_of_registers: int,
        unit_id: int,
        encoding: str = "ascii",
    ) -> str:
        """Read holding registers and decode them as a string.

        Args:
            start_address: Starting address of the registers to read.
            length: Length of the string to decode.
            unit_id: Unit ID.

        Returns:
            Decoded string value.

        """
        format_struct = struct.Struct(f">{number_of_registers * 2}s")
        string_bytes = await self.read_simple_struct_format(start_address, format_struct=format_struct, unit_id=unit_id)
        return string_bytes.decode(encoding)


class HoldingRegisterWriteMixin(SupportsExecuteAsync):
    """Mixin for holding register write operations."""

    async def write_struct_format(
        self,
        start_address: int,
        values: tuple[Any, ...],
        *,
        format_struct: struct.Struct,
        unit_id: int,
    ) -> None:
        """Write holding registers using the provided struct format.

        Args:
            start_address: Starting address of the registers to write
            values: Values to encode and write
            format_struct: Struct format to encode the values
            unit_id: Unit ID

        Returns:
            None

        """
        return await self.execute(
            RawWriteMultipleRegistersPDU(
                start_address,
                content=format_struct.pack(*values),
            ),
            unit_id=unit_id,
        )

    async def write_simple_struct_format(
        self,
        address: int,
        value: Any,
        *,
        format_struct: struct.Struct,
        unit_id: int,
    ) -> Any:
        """Write a single value to holding registers using the provided struct format.

        Args:
            address: Address of the register to write.
            value: Value to encode and write.
            format_struct: Struct format to encode the value.
            unit_id: Unit ID.

        Returns:
            None

        """
        return await self.write_struct_format(
            address,
            values=(value,),
            format_struct=format_struct,
            unit_id=unit_id,
        )

    async def write_uint16(
        self,
        address: int,
        value: int,
        *,
        unit_id: int,
    ) -> Any:
        """Write an unsigned 16-bit integer to holding registers.

        An unsigned 16-bit integer is 1 holding register wide.

        Args:
            address: Address of the register to write.
            value: Unsigned 16-bit integer value to write.
            unit_id: Unit ID.

        Returns:
            None

        """
        if not (0 <= value <= 0xFFFF):
            msg = "Value out of range for uint16 (0-65535)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=struct.Struct(">H"),
            unit_id=unit_id,
        )

    async def write_uint32(
        self,
        address: int,
        value: int,
        *,
        unit_id: int,
    ) -> Any:
        """Write an unsigned 32-bit integer to holding registers.

        An unsigned 32-bit integer is 2 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Unsigned 32-bit integer value to write.
            unit_id: Unit ID.

        Returns:
            None

        """
        msg = "Value out of range for uint32 (0-4294967295)."
        if not (0 <= value <= 0xFFFF_FFFF):
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=struct.Struct(">I"),
            unit_id=unit_id,
        )

    async def write_uint64(
        self,
        address: int,
        value: int,
        *,
        unit_id: int,
    ) -> Any:
        """Write an unsigned 64-bit integer to holding registers.

        An unsigned 64-bit integer is 4 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Unsigned 64-bit integer value to write.
            unit_id: Unit ID.

        Returns:
            None

        """
        if not (0 <= value <= 0xFFFF_FFFF_FFFF_FFFF):
            msg = "Value out of range for uint64 (0-18446744073709551615)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=struct.Struct(">Q"),
            unit_id=unit_id,
        )

    async def write_int16(
        self,
        address: int,
        value: int,
        *,
        unit_id: int,
    ) -> Any:
        """Write a signed 16-bit integer to holding registers.

        A signed 16-bit integer is 1 holding register wide.

        Args:
            address: Address of the register to write.
            value: Signed 16-bit integer value to write.
            unit_id: Unit ID.

        Returns:
            None

        """
        if not (-0x8000 <= value <= 0x7FFF):
            msg = "Value out of range for int16 (-32768 to 32767)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=struct.Struct(">h"),
            unit_id=unit_id,
        )

    async def write_int32(
        self,
        address: int,
        value: int,
        *,
        unit_id: int,
    ) -> Any:
        """Write a signed 32-bit integer to holding registers.

        A signed 32-bit integer is 2 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Signed 32-bit integer value to write.
            unit_id: Unit ID.

        Returns:
            None

        """
        if not (-0x8000_0000 <= value <= 0x7FFF_FFFF):
            msg = "Value out of range for int32 (-2147483648 to 2147483647)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=struct.Struct(">i"),
            unit_id=unit_id,
        )

    async def write_int64(
        self,
        address: int,
        value: int,
        *,
        unit_id: int,
    ) -> Any:
        """Write a signed 64-bit integer to holding registers.

        A signed 64-bit integer is 4 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Signed 64-bit integer value to write.
            unit_id: Unit ID.

        Returns:
            None

        """
        if not (-0x8000_0000_0000_0000 <= value <= 0x7FFF_FFFF_FFFF_FFFF):
            msg = "Value out of range for int64 (-9223372036854775808 to 9223372036854775807)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=struct.Struct(">q"),
            unit_id=unit_id,
        )

    async def write_float(
        self,
        address: int,
        value: float,
        *,
        unit_id: int,
    ) -> Any:
        """Write a float to holding registers.

        A float is 2 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Float value to write.
            unit_id: Unit ID.

        Returns:
            None

        """
        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=struct.Struct(">f"),
            unit_id=unit_id,
        )

    async def write_double(
        self,
        address: int,
        value: float,
        *,
        unit_id: int,
    ) -> Any:
        """Write a double to holding registers.

        A double is 4 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Float value to write.
            unit_id: Unit ID.

        Returns:
            None

        """
        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=struct.Struct(">d"),
            unit_id=unit_id,
        )

    async def write_string(
        self,
        start_address: int,
        value: str,
        *,
        number_of_registers: int,
        unit_id: int,
        encoding: str = "ascii",
    ) -> Any:
        """Write a string to holding registers.

        Args:
            start_address: Starting address of the registers to write.
            value: String value to write.
            number_of_registers: Number of registers to write.
            unit_id: Unit ID.
            encoding: Encoding format for the string (default is "ascii").

        Returns:
            None

        """
        max_length = number_of_registers * 2
        value_bytes = value.encode(encoding)
        if len(value_bytes) > max_length:
            msg = f"String length exceeds maximum size of {max_length} bytes."
            raise ValueError(msg)

        format_struct = struct.Struct(f">{number_of_registers * 2}s")
        # Pad with null bytes if necessary
        value_bytes = value_bytes.rjust(format_struct.size, b"\x00")

        return await self.write_simple_struct_format(
            start_address,
            value_bytes,
            format_struct=format_struct,
            unit_id=unit_id,
        )
