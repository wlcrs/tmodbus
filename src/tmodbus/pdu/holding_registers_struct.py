"""Holding Registers utilities."""

from struct import Struct
from typing import Any, Literal, Protocol, TypeVar, cast

from tmodbus.utils.word_aware_struct import WordOrderAwareStruct

from .base import BasePDU
from .holding_registers import RawReadHoldingRegistersPDU, RawReadInputRegistersPDU, RawWriteMultipleRegistersPDU

RT = TypeVar("RT")


class SupportsExecuteAsync(Protocol):
    """Protocol for classes that support the execute method."""

    async def execute(self, pdu: BasePDU[RT]) -> RT:
        """Send the PDU and return the response."""
        ...


class HoldingRegisterReadMixin(SupportsExecuteAsync):
    """Mixin for holding register read operations."""

    word_order: Literal["big", "little"]

    def __init__(self, word_order: Literal["big", "little"] = "big") -> None:
        """Initialize the mixin.

        Args:
            word_order: Word order for multi-register values ('big' or 'little').

        """
        self.word_order = word_order

    async def read_struct_format[RT](
        self,
        start_address: int,
        *,
        format_struct: Struct | str,
        input_register: bool = False,
    ) -> tuple[Any, ...]:
        """Read holding registers and decode them using the provided struct format.

        Args:
            start_address: Starting address of the registers to read
            format_struct: Struct format to decode the response
            input_register: Whether to read holding registers (False) or input registers (True)

        Returns:
            Decoded response data using the provided struct format

        """
        pdu_class = RawReadInputRegistersPDU if input_register else RawReadHoldingRegistersPDU

        if isinstance(format_struct, Struct):
            format_struct = WordOrderAwareStruct(format_struct.format, word_order=self.word_order)
        if isinstance(format_struct, str):
            format_struct = WordOrderAwareStruct(format_struct, word_order=self.word_order)

        response_bytes = await self.execute(
            pdu_class(
                start_address,
                quantity=format_struct.size // 2,
            )
        )
        return format_struct.unpack(response_bytes)

    async def read_simple_struct_format(
        self,
        start_address: int,
        *,
        format_struct: Struct | str,
        input_register: bool = False,
    ) -> Any:
        """Read holding registers and decode them as a single value using the provided struct format.

        Args:
            struct_format: Struct format to decode the response
            start_address: Starting address of the registers to read
            format_struct: Struct format to decode the response
            input_register: Whether to read holding registers (False) or input registers (True)

        Returns:
            Decoded response data as a single value

        """
        return (
            await self.read_struct_format(
                start_address,
                format_struct=format_struct,
                input_register=input_register,
            )
        )[0]

    async def read_uint16(
        self,
        start_address: int,
        *,
        input_register: bool = False,
    ) -> int:
        """Read holding registers and decode them as an unsigned 16-bit integer.

        An unsigned 16-bit integer is 2 bytes wide (1 register).

        Args:
            start_address: Starting address of the registers to read.
            input_register: Whether to read holding registers (False) or input registers (True).

        Returns:
            Decoded unsigned 16-bit integer.

        """
        return cast(
            "int",
            await self.read_simple_struct_format(
                start_address,
                format_struct=">H",
                input_register=input_register,
            ),
        )

    async def read_uint32(
        self,
        start_address: int,
        *,
        input_register: bool = False,
    ) -> int:
        """Read holding registers and decode them as an unsigned 32-bit integer.

        An unsigned 32-bit integer is 4 bytes wide (2 registers).

        Args:
            start_address: Starting address of the registers to read.
            input_register: Whether to read holding registers (False) or input registers (True).

        Returns:
            Decoded unsigned 32-bit integer.

        """
        return cast(
            "int",
            await self.read_simple_struct_format(
                start_address,
                format_struct=">I",
                input_register=input_register,
            ),
        )

    async def read_uint64(
        self,
        start_address: int,
        *,
        input_register: bool = False,
    ) -> int:
        """Read holding registers and decode them as an unsigned 64-bit integer.

        An unsigned 64-bit integer is 8 bytes wide (4 registers).

        Args:
            start_address: Starting address of the registers to read.
            input_register: Whether to read holding registers (False) or input registers (True).

        Returns:
            Decoded unsigned 64-bit integer.

        """
        return cast(
            "int",
            await self.read_simple_struct_format(
                start_address,
                format_struct=">Q",
                input_register=input_register,
            ),
        )

    async def read_int16(
        self,
        start_address: int,
        *,
        input_register: bool = False,
    ) -> int:
        """Read holding registers and decode them as a signed 16-bit integer.

        A signed 16-bit integer is 2 bytes wide (1 register).

        Args:
            start_address: Starting address of the registers to read.
            input_register: Whether to read holding registers (False) or input registers (True).


        Returns:
            Decoded signed 16-bit integer.

        """
        return cast(
            "int",
            await self.read_simple_struct_format(
                start_address,
                format_struct=">h",
                input_register=input_register,
            ),
        )

    async def read_int32(
        self,
        start_address: int,
        *,
        input_register: bool = False,
    ) -> int:
        """Read holding registers and decode them as a signed 32-bit integer.

        A signed 32-bit integer is 4 bytes wide (2 registers).

        Args:
            start_address: Starting address of the registers to read.
            input_register: Whether to read holding registers (False) or input registers (True).

        Returns:
            Decoded signed 32-bit integer.

        """
        return cast(
            "int",
            await self.read_simple_struct_format(
                start_address,
                format_struct=">i",
                input_register=input_register,
            ),
        )

    async def read_int64(
        self,
        start_address: int,
        *,
        input_register: bool = False,
    ) -> int:
        """Read holding registers and decode them as a signed 64-bit integer.

        A signed 64-bit integer is 8 bytes wide (4 registers).

        Args:
            start_address: Starting address of the registers to read.
            input_register: Whether to read holding registers (False) or input registers (True).

        Returns:
            Decoded signed 64-bit integer.

        """
        return cast(
            "int",
            await self.read_simple_struct_format(
                start_address,
                format_struct=">q",
                input_register=input_register,
            ),
        )

    async def read_float(
        self,
        start_address: int,
        *,
        input_register: bool = False,
    ) -> float:
        """Read holding registers and decode them as a float.

        A float is 4 bytes wide (2 registers).

        Args:
            start_address: Starting address of the registers to read.
            input_register: Whether to read holding registers (False) or input registers (True).

        Returns:
            Decoded float value.

        """
        return cast(
            "float",
            await self.read_simple_struct_format(
                start_address,
                format_struct=">f",
                input_register=input_register,
            ),
        )

    async def read_string(
        self,
        start_address: int,
        *,
        number_of_registers: int,
        input_register: bool = False,
        encoding: str = "ascii",
    ) -> str:
        """Read holding registers and decode them as a string.

        Args:
            start_address: Starting address of the registers to read.
            length: Length of the string to decode.
            number_of_registers: Number of registers to read.
            input_register: Whether to read holding registers (False) or input registers (True).
            encoding: Encoding format for the string (default is "ascii").

        Returns:
            Decoded string value.

        """
        format_struct = WordOrderAwareStruct(f">{number_of_registers * 2}s", word_order=self.word_order)
        string_bytes = cast(
            "bytes",
            await self.read_simple_struct_format(
                start_address,
                format_struct=format_struct,
                input_register=input_register,
            ),
        )
        return string_bytes.decode(encoding)


class HoldingRegisterWriteMixin(SupportsExecuteAsync):
    """Mixin for holding register write operations."""

    word_order: Literal["big", "little"]

    def __init__(self, word_order: Literal["big", "little"] = "big") -> None:
        """Initialize the mixin.

        Args:
            word_order: Word order for multi-register values ('big' or 'little').

        """
        self.word_order = word_order

    async def write_struct_format(
        self,
        start_address: int,
        values: tuple[Any, ...],
        *,
        format_struct: Struct | str,
    ) -> int:
        """Write holding registers using the provided struct format.

        Args:
            start_address: Starting address of the registers to write
            values: Values to encode and write
            format_struct: Struct format to encode the values

        Returns:
            The number of registers that have been written.

        """
        if isinstance(format_struct, Struct):
            format_struct = WordOrderAwareStruct(format_struct.format, word_order=self.word_order)
        if isinstance(format_struct, str):
            format_struct = WordOrderAwareStruct(format_struct, word_order=self.word_order)

        return await self.execute(
            RawWriteMultipleRegistersPDU(
                start_address,
                content=format_struct.pack(*values),
            ),
        )

    async def write_simple_struct_format(
        self,
        address: int,
        value: Any,
        *,
        format_struct: Struct | str,
    ) -> Any:
        """Write a single value to holding registers using the provided struct format.

        Args:
            address: Address of the register to write.
            value: Value to encode and write.
            format_struct: Struct format to encode the value.

        Returns:
            None

        """
        return await self.write_struct_format(
            address,
            values=(value,),
            format_struct=format_struct,
        )

    async def write_uint16(
        self,
        address: int,
        value: int,
    ) -> Any:
        """Write an unsigned 16-bit integer to holding registers.

        An unsigned 16-bit integer is 1 holding register wide.

        Args:
            address: Address of the register to write.
            value: Unsigned 16-bit integer value to write.

        Returns:
            None

        """
        if not (0 <= value <= 0xFFFF):
            msg = "Value out of range for uint16 (0-65535)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=">H",
        )

    async def write_uint32(
        self,
        address: int,
        value: int,
    ) -> Any:
        """Write an unsigned 32-bit integer to holding registers.

        An unsigned 32-bit integer is 2 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Unsigned 32-bit integer value to write.

        Returns:
            None

        """
        msg = "Value out of range for uint32 (0-4294967295)."
        if not (0 <= value <= 0xFFFF_FFFF):
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=">I",
        )

    async def write_uint64(
        self,
        address: int,
        value: int,
    ) -> Any:
        """Write an unsigned 64-bit integer to holding registers.

        An unsigned 64-bit integer is 4 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Unsigned 64-bit integer value to write.

        Returns:
            None

        """
        if not (0 <= value <= 0xFFFF_FFFF_FFFF_FFFF):
            msg = "Value out of range for uint64 (0-18446744073709551615)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=">Q",
        )

    async def write_int16(
        self,
        address: int,
        value: int,
    ) -> Any:
        """Write a signed 16-bit integer to holding registers.

        A signed 16-bit integer is 1 holding register wide.

        Args:
            address: Address of the register to write.
            value: Signed 16-bit integer value to write.

        Returns:
            None

        """
        if not (-0x8000 <= value <= 0x7FFF):
            msg = "Value out of range for int16 (-32768 to 32767)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=">h",
        )

    async def write_int32(
        self,
        address: int,
        value: int,
    ) -> Any:
        """Write a signed 32-bit integer to holding registers.

        A signed 32-bit integer is 2 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Signed 32-bit integer value to write.

        Returns:
            None

        """
        if not (-0x8000_0000 <= value <= 0x7FFF_FFFF):
            msg = "Value out of range for int32 (-2147483648 to 2147483647)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=">i",
        )

    async def write_int64(
        self,
        address: int,
        value: int,
    ) -> Any:
        """Write a signed 64-bit integer to holding registers.

        A signed 64-bit integer is 4 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Signed 64-bit integer value to write.

        Returns:
            None

        """
        if not (-0x8000_0000_0000_0000 <= value <= 0x7FFF_FFFF_FFFF_FFFF):
            msg = "Value out of range for int64 (-9223372036854775808 to 9223372036854775807)."
            raise ValueError(msg)

        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=">q",
        )

    async def write_float(
        self,
        address: int,
        value: float,
    ) -> Any:
        """Write a float to holding registers.

        A float is 2 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Float value to write.

        Returns:
            None

        """
        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=">f",
        )

    async def write_double(
        self,
        address: int,
        value: float,
    ) -> Any:
        """Write a double to holding registers.

        A double is 4 holding registers wide.

        Args:
            address: Address of the register to write.
            value: Float value to write.

        Returns:
            None

        """
        return await self.write_simple_struct_format(
            address,
            value,
            format_struct=">d",
        )

    async def write_string(
        self,
        start_address: int,
        value: str,
        *,
        number_of_registers: int,
        encoding: str = "ascii",
    ) -> Any:
        """Write a string to holding registers.

        Args:
            start_address: Starting address of the registers to write.
            value: String value to write.
            number_of_registers: Number of registers to write.
            encoding: Encoding format for the string (default is "ascii").

        Returns:
            None

        """
        max_length = number_of_registers * 2
        value_bytes = value.encode(encoding)
        if len(value_bytes) > max_length:
            msg = f"String length exceeds maximum size of {max_length} bytes."
            raise ValueError(msg)

        format_struct = WordOrderAwareStruct(f">{number_of_registers * 2}s", word_order=self.word_order)
        # Pad with null bytes if necessary
        value_bytes = value_bytes.ljust(format_struct.size, b"\x00")

        return await self.write_simple_struct_format(
            start_address,
            value_bytes,
            format_struct=format_struct,
        )
