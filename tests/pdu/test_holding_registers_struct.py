"""Tests for holding_registers_struct module."""

import math
import struct
from typing import Literal
from unittest.mock import AsyncMock

import pytest
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.pdu.holding_registers_struct import HoldingRegisterReadMixin, HoldingRegisterWriteMixin
from tmodbus.utils.word_aware_struct import WordOrderAwareStruct


class MockClient(HoldingRegisterReadMixin, HoldingRegisterWriteMixin):
    """Mock client for testing mixins."""

    execute: AsyncMock

    def __init__(self, word_order: Literal["big", "little"] = "big") -> None:
        """Mock Client."""
        HoldingRegisterReadMixin.__init__(self, word_order=word_order)
        HoldingRegisterWriteMixin.__init__(self, word_order=word_order)
        self.execute = AsyncMock()


class TestHoldingRegisterReadMixin:
    """Test HoldingRegisterReadMixin class."""

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_read_struct_format(self, word_order: Literal["big", "little"]) -> None:
        """Test read_struct_format with both word orders."""
        client = MockClient(word_order=word_order)
        # Mock response: 4 bytes representing uint32
        client.execute.return_value = b"\x0a\x0b\x0c\x0d"

        format_struct = WordOrderAwareStruct(">I", word_order=word_order)
        result = await client.read_struct_format(100, format_struct=format_struct)

        # Verify execute was called with correct PDU
        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.start_address == 100
        assert pdu.quantity == 2  # 4 bytes = 2 registers

        # Verify result
        assert isinstance(result, tuple)
        assert len(result) == 1

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_read_struct_format_string_format(self, word_order: Literal["big", "little"]) -> None:
        """Test read_struct_format with string format (covers line 56)."""
        client = MockClient(word_order=word_order)
        # Mock response: 4 bytes representing uint32
        client.execute.return_value = b"\x0a\x0b\x0c\x0d"

        # Pass a string instead of WordOrderAwareStruct to test line 56
        result = await client.read_struct_format(100, format_struct=">I")

        # Verify execute was called with correct PDU
        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.start_address == 100
        assert pdu.quantity == 2  # 4 bytes = 2 registers

        # Verify result
        assert isinstance(result, tuple)
        assert len(result) == 1

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_read_struct_format_input_register(self, word_order: Literal["big", "little"]) -> None:
        """Test read_struct_format with input registers."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = b"\x01\x02"

        format_struct = WordOrderAwareStruct(">H", word_order=word_order)
        result = await client.read_struct_format(50, format_struct=format_struct, input_register=True)

        assert client.execute.called
        assert result == (0x0102,)

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_read_simple_struct_format(self, word_order: Literal["big", "little"]) -> None:
        """Test read_simple_struct_format returns single value."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = b"\x12\x34"

        format_struct = WordOrderAwareStruct(">H", word_order=word_order)
        result = await client.read_simple_struct_format(100, format_struct=format_struct)

        # Should return single value, not tuple
        assert result == 0x1234

    @pytest.mark.parametrize(
        ("word_order", "expected"),
        [
            ("big", 0x1234),
            ("little", 0x1234),  # Single register, no swapping
        ],
    )
    async def test_read_uint16(self, word_order: Literal["big", "little"], expected: int) -> None:
        """Test read_uint16 with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = b"\x12\x34"

        result = await client.read_uint16(100)

        assert result == expected
        assert client.execute.called

    @pytest.mark.parametrize(
        ("word_order", "response", "expected"),
        [
            ("big", b"\x0a\x0b\x0c\x0d", 0x0A0B0C0D),
            ("little", b"\x0c\x0d\x0a\x0b", 0x0A0B0C0D),
        ],
    )
    async def test_read_uint32(self, word_order: Literal["big", "little"], response: bytes, expected: int) -> None:
        """Test read_uint32 with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = response

        result = await client.read_uint32(100)

        assert result == expected

    @pytest.mark.parametrize(
        ("word_order", "response", "expected"),
        [
            ("big", b"\x0a\x0b\x0c\x0d\x0e\x0f\x01\x02", 0x0A0B0C0D0E0F0102),
            ("little", b"\x01\x02\x0e\x0f\x0c\x0d\x0a\x0b", 0x0A0B0C0D0E0F0102),
        ],
    )
    async def test_read_uint64(self, word_order: Literal["big", "little"], response: bytes, expected: int) -> None:
        """Test read_uint64 with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = response

        result = await client.read_uint64(100)

        assert result == expected

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_read_int16(self, word_order: Literal["big", "little"]) -> None:
        """Test read_int16 with negative value."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = b"\xff\xff"  # -1

        result = await client.read_int16(100)

        assert result == -1

    @pytest.mark.parametrize(
        ("word_order", "response", "expected"),
        [
            ("big", b"\x0a\x0b\x0c\x0d", 0x0A0B0C0D),
            ("little", b"\x0c\x0d\x0a\x0b", 0x0A0B0C0D),
            ("big", b"\xff\xff\xff\xff", -1),
            ("little", b"\xff\xff\xff\xff", -1),
            ("big", b"\xff\xff\xff\xfe", -2),
            ("little", b"\xff\xfe\xff\xff", -2),
            ("big", b"\x80\x00\x00\x00", -2147483648),  # Min int32
            ("little", b"\x00\x00\x80\x00", -2147483648),
            ("big", b"\x7f\xff\xff\xff", 2147483647),  # Max int32
            ("little", b"\xff\xff\x7f\xff", 2147483647),
        ],
    )
    async def test_read_int32(self, word_order: Literal["big", "little"], response: bytes, expected: int) -> None:
        """Test read_int32 with both word orders and negative values."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = response

        result = await client.read_int32(100)

        assert result == expected

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_read_int64(self, word_order: Literal["big", "little"]) -> None:
        """Test read_int64 with negative value."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = b"\xff\xff\xff\xff\xff\xff\xff\xff"  # -1

        result = await client.read_int64(100)

        assert result == -1

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_read_float(self, word_order: Literal["big", "little"]) -> None:
        """Test read_float with both word orders."""
        client = MockClient(word_order=word_order)
        # Encode 1.0 as float and apply word order

        float_bytes = struct.pack(">f", 1.0)
        if word_order == "little":
            # Swap register order for little endian
            float_bytes = float_bytes[2:4] + float_bytes[0:2]

        client.execute.return_value = float_bytes

        result = await client.read_float(100)

        assert abs(result - 1.0) < 0.0001  # Float comparison with tolerance

    @pytest.mark.parametrize(
        ("word_order", "response"),
        [
            ("big", b"HELLO\x00\x00\x00"),
            ("little", b"\x00\x00O\x00LLHE"),  # Word-swapped format from device
        ],
    )
    async def test_read_string(self, word_order: Literal["big", "little"], response: bytes) -> None:
        """Test read_string with both word orders."""
        client = MockClient(word_order=word_order)
        # 4 registers = 8 bytes
        client.execute.return_value = response

        result = await client.read_string(100, number_of_registers=4)

        assert "HELLO" in result

    @pytest.mark.parametrize(
        ("word_order", "response"),
        [
            ("big", b"TEST\x00\x00\x00\x00"),
            ("little", b"\x00\x00\x00\x00STTE"),  # Word-swapped format from device
        ],
    )
    async def test_read_string_with_encoding(self, word_order: Literal["big", "little"], response: bytes) -> None:
        """Test read_string with custom encoding."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = response

        result = await client.read_string(100, number_of_registers=4, encoding="utf-8")

        assert "TEST" in result

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_read_input_register_flag(self, word_order: Literal["big", "little"]) -> None:
        """Test that input_register flag is passed through correctly."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = b"\x12\x34"

        await client.read_uint16(100, input_register=True)

        # Verify the PDU type by checking the execute call
        pdu = client.execute.call_args[0][0]
        # Input register PDU should be different from holding register PDU
        assert pdu.__class__.__name__ == "RawReadInputRegistersPDU"


class TestHoldingRegisterWriteMixin:
    """Test HoldingRegisterWriteMixin class."""

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_write_struct_format(self, word_order: Literal["big", "little"]) -> None:
        """Test write_struct_format with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 2  # Number of registers written

        format_struct = WordOrderAwareStruct(">I", word_order=word_order)
        result = await client.write_struct_format(100, (0x0A0B0C0D,), format_struct=format_struct)

        assert result == 2
        assert client.execute.called

        # Verify PDU
        pdu = client.execute.call_args[0][0]
        assert pdu.start_address == 100
        assert len(pdu.content) == 4  # 4 bytes for uint32

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_write_simple_struct_format(self, word_order: Literal["big", "little"]) -> None:
        """Test write_simple_struct_format."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 1

        format_struct = WordOrderAwareStruct(">H", word_order=word_order)
        result = await client.write_simple_struct_format(100, 0x1234, format_struct=format_struct)

        assert result == 1
        assert client.execute.called

    @pytest.mark.parametrize(
        ("word_order", "expected_bytes"),
        [
            ("big", b"\x12\x34"),
            ("little", b"\x12\x34"),  # Single register, no swapping
        ],
    )
    async def test_write_uint16(self, word_order: Literal["big", "little"], expected_bytes: bytes) -> None:
        """Test write_uint16 with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 1

        await client.write_uint16(100, 0x1234)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.content == expected_bytes

    async def test_write_uint16_out_of_range_low(self) -> None:
        """Test write_uint16 with value below range."""
        client = MockClient()

        with pytest.raises(ValueError, match="Value out of range for uint16"):
            await client.write_uint16(100, -1)

    async def test_write_uint16_out_of_range_high(self) -> None:
        """Test write_uint16 with value above range."""
        client = MockClient()

        with pytest.raises(ValueError, match="Value out of range for uint16"):
            await client.write_uint16(100, 0x10000)

    @pytest.mark.parametrize(
        ("word_order", "expected_bytes"),
        [
            ("big", b"\x12\x34\x56\x78"),
            ("little", b"\x56\x78\x12\x34"),  # Swapped register order
        ],
    )
    async def test_write_uint32(self, word_order: Literal["big", "little"], expected_bytes: bytes) -> None:
        """Test write_uint32 with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 2

        await client.write_uint32(100, 0x12345678)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.content == expected_bytes

    async def test_write_uint32_out_of_range(self) -> None:
        """Test write_uint32 with value out of range."""
        client = MockClient()

        with pytest.raises(ValueError, match="Value out of range for uint32"):
            await client.write_uint32(100, 0x1_0000_0000)

    @pytest.mark.parametrize(
        ("word_order", "expected_bytes"),
        [
            ("big", b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"),
            ("little", b"\xde\xf0\x9a\xbc\x56\x78\x12\x34"),  # Swapped register order
        ],
    )
    async def test_write_uint64(self, word_order: Literal["big", "little"], expected_bytes: bytes) -> None:
        """Test write_uint64 with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 4

        await client.write_uint64(100, 0x123456789ABCDEF0)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.content == expected_bytes

    async def test_write_uint64_out_of_range(self) -> None:
        """Test write_uint64 with value out of range."""
        client = MockClient()

        with pytest.raises(ValueError, match="Value out of range for uint64"):
            await client.write_uint64(100, 0x1_0000_0000_0000_0000)

    @pytest.mark.parametrize(
        ("word_order", "expected_bytes"),
        [
            ("big", b"\xfb\x2e"),  # -1234 in signed 16-bit
            ("little", b"\xfb\x2e"),  # Single register, no swapping
        ],
    )
    async def test_write_int16(self, word_order: Literal["big", "little"], expected_bytes: bytes) -> None:
        """Test write_int16 with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 1

        await client.write_int16(100, -1234)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.content == expected_bytes

    async def test_write_int16_out_of_range_low(self) -> None:
        """Test write_int16 with value below range."""
        client = MockClient()

        with pytest.raises(ValueError, match="Value out of range for int16"):
            await client.write_int16(100, -0x8001)

    async def test_write_int16_out_of_range_high(self) -> None:
        """Test write_int16 with value above range."""
        client = MockClient()

        with pytest.raises(ValueError, match="Value out of range for int16"):
            await client.write_int16(100, 0x8000)

    @pytest.mark.parametrize(
        ("word_order", "expected_bytes"),
        [
            ("big", b"\xff\xfe\x1d\xc0"),  # -123456 in signed 32-bit
            ("little", b"\x1d\xc0\xff\xfe"),  # Swapped register order
        ],
    )
    async def test_write_int32(self, word_order: Literal["big", "little"], expected_bytes: bytes) -> None:
        """Test write_int32 with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 2

        await client.write_int32(100, -123456)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.content == expected_bytes

    async def test_write_int32_out_of_range(self) -> None:
        """Test write_int32 with value out of range."""
        client = MockClient()

        with pytest.raises(ValueError, match="Value out of range for int32"):
            await client.write_int32(100, -0x8000_0001)

    @pytest.mark.parametrize(
        ("word_order", "expected_bytes"),
        [
            ("big", b"\xff\xff\xff\xff\xf8\xa4\x32\xeb"),  # -123456789 in signed 64-bit
            ("little", b"\x32\xeb\xf8\xa4\xff\xff\xff\xff"),  # Swapped register order
        ],
    )
    async def test_write_int64(self, word_order: Literal["big", "little"], expected_bytes: bytes) -> None:
        """Test write_int64 with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 4

        await client.write_int64(100, -123456789)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.content == expected_bytes

    async def test_write_int64_out_of_range(self) -> None:
        """Test write_int64 with value out of range."""
        client = MockClient()

        with pytest.raises(ValueError, match="Value out of range for int64"):
            await client.write_int64(100, -0x8000_0000_0000_0001)

    @pytest.mark.parametrize(
        ("word_order", "expected_bytes"),
        [
            ("big", b"\x40\x49\x0f\xd0"),  # 3.14159 as float
            ("little", b"\x0f\xd0\x40\x49"),  # Swapped register order
        ],
    )
    async def test_write_float(self, word_order: Literal["big", "little"], expected_bytes: bytes) -> None:
        """Test write_float with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 2

        await client.write_float(100, 3.14159)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.content == expected_bytes

    @pytest.mark.parametrize(
        ("word_order", "expected_bytes"),
        [
            ("big", b"\x40\x09\x21\xfb\x54\x44\x2d\x18"),  # pi as double
            ("little", b"\x2d\x18\x54\x44\x21\xfb\x40\x09"),  # Swapped register order
        ],
    )
    async def test_write_double(self, word_order: Literal["big", "little"], expected_bytes: bytes) -> None:
        """Test write_double with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 4

        await client.write_double(100, 3.141592653589793)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.content == expected_bytes

    @pytest.mark.parametrize(
        ("word_order", "expected_bytes"),
        [
            ("big", b"HELLO\x00\x00\x00"),  # Right-padded with nulls (ljust)
            ("little", b"\x00\x00O\x00LLHE"),  # Swapped register order
        ],
    )
    async def test_write_string(self, word_order: Literal["big", "little"], expected_bytes: bytes) -> None:
        """Test write_string with both word orders."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 4

        await client.write_string(100, "HELLO", number_of_registers=4)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        assert pdu.content == expected_bytes

    async def test_write_string_too_long(self) -> None:
        """Test write_string with string too long for register count."""
        client = MockClient()

        with pytest.raises(ValueError, match="String length exceeds maximum size"):
            await client.write_string(100, "VERYLONGSTRING", number_of_registers=2)

    @pytest.mark.parametrize("word_order", ["big", "little"])
    async def test_write_string_with_encoding(self, word_order: Literal["big", "little"]) -> None:
        """Test write_string with custom encoding."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 3

        await client.write_string(100, "TEST", number_of_registers=3, encoding="utf-8")

        assert client.execute.called

    @pytest.mark.parametrize(
        ("word_order", "bytes_result"),
        [
            ("big", b"TEST\x00\x00\x00\x00"),
            ("little", b"\x00\x00\x00\x00STTE"),
        ],
    )
    async def test_write_string_padding(self, word_order: Literal["big", "little"], bytes_result: bytes) -> None:
        """Test that short strings are padded correctly."""
        client = MockClient(word_order=word_order)
        client.execute.return_value = 4

        await client.write_string(100, "TEST", number_of_registers=4)

        assert client.execute.called
        pdu = client.execute.call_args[0][0]
        # Should be padded to 8 bytes (4 registers)
        assert len(pdu.content) == 8
        # Verify content contains the string (word order may affect byte arrangement)
        assert pdu.content == bytes_result


class TestRoundTripReadWrite:
    """Test round-trip write then read operations."""

    @pytest.mark.parametrize("word_order", ["big", "little"])
    @pytest.mark.parametrize(
        "value",
        [
            0,
            1,
            100,
            1234,
            32767,  # Max positive int16
            65535,  # Max uint16
            42,  # Random value
            0x1234,  # Specific hex pattern
        ],
    )
    async def test_roundtrip_uint16(self, word_order: Literal["big", "little"], value: int) -> None:
        """Test writing and reading back uint16 values."""
        client = MockClient(word_order=word_order)

        # Capture the written bytes
        written_bytes = None

        def capture_write(pdu: BaseClientPDU[int]) -> int:
            nonlocal written_bytes
            written_bytes = pdu.content  # type: ignore[attr-defined]
            return 1

        client.execute.side_effect = capture_write
        await client.write_uint16(100, value)

        # Now read it back
        client.execute.side_effect = None
        client.execute.return_value = written_bytes
        result = await client.read_uint16(100)

        assert result == value

    @pytest.mark.parametrize("word_order", ["big", "little"])
    @pytest.mark.parametrize(
        "value",
        [
            -32768,  # Min int16
            -1,
            0,
            1,
            100,
            32767,  # Max int16
            -12345,  # Random negative
            12345,  # Random positive
        ],
    )
    async def test_roundtrip_int16(self, word_order: Literal["big", "little"], value: int) -> None:
        """Test writing and reading back int16 values."""
        client = MockClient(word_order=word_order)

        written_bytes = None

        def capture_write(pdu: BaseClientPDU[int]) -> int:
            nonlocal written_bytes
            written_bytes = pdu.content  # type: ignore[attr-defined]
            return 1

        client.execute.side_effect = capture_write
        await client.write_int16(100, value)

        client.execute.side_effect = None
        client.execute.return_value = written_bytes
        result = await client.read_int16(100)

        assert result == value

    @pytest.mark.parametrize("word_order", ["big", "little"])
    @pytest.mark.parametrize(
        "value",
        [
            0,
            1,
            1000,
            0x12345678,
            0xFFFFFFFF,  # Max uint32
            0x80000000,  # 2^31
            0xDEADBEEF,  # Common test pattern
        ],
    )
    async def test_roundtrip_uint32(self, word_order: Literal["big", "little"], value: int) -> None:
        """Test writing and reading back uint32 values."""
        client = MockClient(word_order=word_order)

        written_bytes = None

        def capture_write(pdu: BaseClientPDU[int]) -> int:
            nonlocal written_bytes
            written_bytes = pdu.content  # type: ignore[attr-defined]
            return 2

        client.execute.side_effect = capture_write
        await client.write_uint32(100, value)

        client.execute.side_effect = None
        client.execute.return_value = written_bytes
        result = await client.read_uint32(100)

        assert result == value

    @pytest.mark.parametrize("word_order", ["big", "little"])
    @pytest.mark.parametrize(
        "value",
        [
            -2147483648,  # Min int32
            -1,
            0,
            1,
            2147483647,  # Max int32
            -123456789,  # Random negative
            123456789,  # Random positive
            -2147483647,  # Min + 1
        ],
    )
    async def test_roundtrip_int32(self, word_order: Literal["big", "little"], value: int) -> None:
        """Test writing and reading back int32 values."""
        client = MockClient(word_order=word_order)

        written_bytes = None

        def capture_write(pdu: BaseClientPDU[int]) -> int:
            nonlocal written_bytes
            written_bytes = pdu.content  # type: ignore[attr-defined]
            return 2

        client.execute.side_effect = capture_write
        await client.write_int32(100, value)

        client.execute.side_effect = None
        client.execute.return_value = written_bytes
        result = await client.read_int32(100)

        assert result == value

    @pytest.mark.parametrize("word_order", ["big", "little"])
    @pytest.mark.parametrize(
        "value",
        [
            0,
            1,
            0xFFFFFFFFFFFFFFFF,  # Max uint64
            0x123456789ABCDEF0,
            0x8000000000000000,  # 2^63
            9223372036854775807,  # Max int64 as uint
            1234567890123456789,  # Random large value
        ],
    )
    async def test_roundtrip_uint64(self, word_order: Literal["big", "little"], value: int) -> None:
        """Test writing and reading back uint64 values."""
        client = MockClient(word_order=word_order)

        written_bytes = None

        def capture_write(pdu: BaseClientPDU[int]) -> int:
            nonlocal written_bytes
            written_bytes = pdu.content  # type: ignore[attr-defined]
            return 4

        client.execute.side_effect = capture_write
        await client.write_uint64(100, value)

        client.execute.side_effect = None
        client.execute.return_value = written_bytes
        result = await client.read_uint64(100)

        assert result == value

    @pytest.mark.parametrize("word_order", ["big", "little"])
    @pytest.mark.parametrize(
        "value",
        [
            -9223372036854775808,  # Min int64
            -1,
            0,
            1,
            9223372036854775807,  # Max int64
            -1234567890123456789,  # Random negative
            1234567890123456789,  # Random positive
        ],
    )
    async def test_roundtrip_int64(self, word_order: Literal["big", "little"], value: int) -> None:
        """Test writing and reading back int64 values."""
        client = MockClient(word_order=word_order)

        written_bytes = None

        def capture_write(pdu: BaseClientPDU[int]) -> int:
            nonlocal written_bytes
            written_bytes = pdu.content  # type: ignore[attr-defined]
            return 4

        client.execute.side_effect = capture_write
        await client.write_int64(100, value)

        client.execute.side_effect = None
        client.execute.return_value = written_bytes
        result = await client.read_int64(100)

        assert result == value

    @pytest.mark.parametrize("word_order", ["big", "little"])
    @pytest.mark.parametrize(
        "value",
        [
            0.0,
            1.0,
            -1.0,
            3.14159,
            -3.14159,
            123.456,
            -999.999,
            1.23e-10,  # Very small positive
            -1.23e-10,  # Very small negative
            1.23e10,  # Large positive
            -1.23e10,  # Large negative
            float("inf"),  # Infinity
            float("-inf"),  # Negative infinity
        ],
    )
    async def test_roundtrip_float(self, word_order: Literal["big", "little"], value: float) -> None:
        """Test writing and reading back float values."""
        client = MockClient(word_order=word_order)

        written_bytes = None

        def capture_write(pdu: BaseClientPDU[float]) -> int:
            nonlocal written_bytes
            written_bytes = pdu.content  # type: ignore[attr-defined]
            return 2

        client.execute.side_effect = capture_write
        await client.write_float(100, value)

        client.execute.side_effect = None
        client.execute.return_value = written_bytes
        result = await client.read_float(100)

        # Handle special float values
        if math.isnan(value):  # NaN check
            assert math.isnan(result)
        elif value == float("inf"):
            assert result == float("inf")
        elif value == float("-inf"):
            assert result == float("-inf")
        else:
            # Float comparison with tolerance
            assert abs(result - value) < abs(value * 1e-6) if value != 0 else abs(result) < 1e-6

    @pytest.mark.parametrize("word_order", ["big", "little"])
    @pytest.mark.parametrize(
        ("value", "num_registers"),
        [
            ("", 2),  # Empty string
            ("A", 2),  # Single char
            ("TEST", 2),  # Exact fit (4 bytes = 2 registers)
            ("HELLO", 4),  # Padded
            ("ABCDEFGH", 4),  # Exact fit (8 bytes = 4 registers)
            ("Short", 5),  # Padded (10 bytes = 5 registers)
            ("X" * 20, 10),  # Long string
            ("123", 3),  # Numeric string
            ("Hello World!", 7),  # With space and punctuation
        ],
    )
    async def test_roundtrip_string(self, word_order: Literal["big", "little"], value: str, num_registers: int) -> None:
        """Test writing and reading back string values."""
        # Skip if string is too long for the number of registers
        if len(value.encode("utf-8")) > num_registers * 2:
            pytest.skip(f"String '{value}' too long for {num_registers} registers")

        client = MockClient(word_order=word_order)

        written_bytes = None

        def _capture_write(pdu: BaseClientPDU[str]) -> int:
            nonlocal written_bytes
            written_bytes = pdu.content  # type: ignore[attr-defined]
            return num_registers

        client.execute.side_effect = _capture_write
        await client.write_string(100, value, number_of_registers=num_registers)

        client.execute.side_effect = None
        client.execute.return_value = written_bytes
        result = await client.read_string(100, number_of_registers=num_registers)

        # Strip null bytes and whitespace for comparison
        assert result.rstrip("\x00") == value

    @pytest.mark.parametrize("word_order", ["big", "little"])
    @pytest.mark.parametrize(
        ("value", "num_registers"),
        [
            ("Café", 4),  # UTF-8 special character
            ("Hello 世界", 10),  # UTF-8 Chinese characters
        ],
    )
    async def test_roundtrip_string_utf8(
        self, word_order: Literal["big", "little"], value: str, num_registers: int
    ) -> None:
        """Test writing and reading back UTF-8 string values."""
        # Skip if string is too long for the number of registers
        if len(value.encode("utf-8")) > num_registers * 2:
            pytest.skip(f"String '{value}' too long for {num_registers} registers")

        client = MockClient(word_order=word_order)

        written_bytes = None

        def _capture_write(pdu: BaseClientPDU[str]) -> int:
            nonlocal written_bytes
            written_bytes = pdu.content  # type: ignore[attr-defined]
            return num_registers

        client.execute.side_effect = _capture_write
        await client.write_string(100, value, number_of_registers=num_registers, encoding="utf-8")

        client.execute.side_effect = None
        client.execute.return_value = written_bytes
        result = await client.read_string(100, number_of_registers=num_registers, encoding="utf-8")

        # Strip null bytes and whitespace for comparison
        assert result.rstrip("\x00") == value
