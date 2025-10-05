"""Tests for word_aware_struct module."""

import struct
from typing import Any, Literal

import pytest
from tmodbus.utils.word_aware_struct import WordOrderAwareStruct


def test_init_odd_size_raises() -> None:
    """Test that odd-sized structs raise ValueError."""
    with pytest.raises(ValueError, match="multiple of 2 bytes"):
        WordOrderAwareStruct(">b")  # 1 byte


@pytest.mark.parametrize(
    ("format_str", "word_order", "value", "expected_bytes"),
    [
        # Single register (2 bytes) - no swapping needed
        (">H", "big", 0x0102, b"\x01\x02"),
        (">H", "little", 0x0102, b"\x01\x02"),
        # 32-bit values (2 registers)
        (">I", "big", 0x0A0B0C0D, b"\x0a\x0b\x0c\x0d"),
        (">I", "little", 0x0A0B0C0D, b"\x0c\x0d\x0a\x0b"),
        (">f", "big", 1.0, b"\x3f\x80\x00\x00"),
        (">f", "little", 1.0, b"\x00\x00\x3f\x80"),  # swapped register order
        # 64-bit values (4 registers)
        (">Q", "big", 0x0A0B0C0D0E0F0102, b"\x0a\x0b\x0c\x0d\x0e\x0f\x01\x02"),
        (">Q", "little", 0x0A0B0C0D0E0F0102, b"\x01\x02\x0e\x0f\x0c\x0d\x0a\x0b"),
        (">d", "big", 1.0, struct.pack(">d", 1.0)),
    ],
)
def test_pack_single_value(
    format_str: str,
    word_order: Literal["little", "big"],
    value: Any,
    expected_bytes: bytes,
) -> None:
    """Test packing single values with different word orders."""
    s = WordOrderAwareStruct(format_str, word_order=word_order)
    result = s.pack(value)
    assert result == expected_bytes


@pytest.mark.parametrize(
    ("format_str", "word_order", "values", "expected_bytes"),
    [
        # Multiple single-register values
        (">HH", "big", (0x0102, 0x0304), b"\x01\x02\x03\x04"),
        (">HH", "little", (0x0102, 0x0304), b"\x01\x02\x03\x04"),
        # Mix of 1-register and 2-register values
        (">HI", "big", (0x0102, 0x09080706), b"\x01\x02\x09\x08\x07\x06"),
        (">HI", "little", (0x0102, 0x09080706), b"\x01\x02\x07\x06\x09\x08"),
        # Mix: H (1 reg) + I (2 reg) + Q (4 reg)
        (
            ">HIQ",
            "big",
            (0x0102, 0x09080706, 0x0A0B0C0D0E0F0102),
            b"\x01\x02\x09\x08\x07\x06\x0a\x0b\x0c\x0d\x0e\x0f\x01\x02",
        ),
        (
            ">HIQ",
            "little",
            (0x0102, 0x09080706, 0x0A0B0C0D0E0F0102),
            b"\x01\x02\x07\x06\x09\x08\x01\x02\x0e\x0f\x0c\x0d\x0a\x0b",
        ),
        # Multiple 2-register values
        (">II", "big", (0x01020304, 0x05060708), b"\x01\x02\x03\x04\x05\x06\x07\x08"),
        (">II", "little", (0x01020304, 0x05060708), b"\x03\x04\x01\x02\x07\x08\x05\x06"),
        # Array notation
        (">2H", "big", (0x0102, 0x0304), b"\x01\x02\x03\x04"),
        (">2I", "little", (0x01020304, 0x05060708), b"\x03\x04\x01\x02\x07\x08\x05\x06"),
    ],
)
def test_pack_multiple_values(
    format_str: str,
    word_order: Literal["little", "big"],
    values: tuple[Any, ...],
    expected_bytes: bytes,
) -> None:
    """Test packing multiple values with different combinations."""
    s = WordOrderAwareStruct(format_str, word_order=word_order)
    result = s.pack(*values)
    assert result == expected_bytes


@pytest.mark.parametrize(
    ("format_str", "word_order", "data", "expected_values"),
    [
        (">H", "big", b"\x01\x02", (0x0102,)),
        (">H", "little", b"\x01\x02", (0x0102,)),
        (">I", "big", b"\x0a\x0b\x0c\x0d", (0x0A0B0C0D,)),
        (">I", "little", b"\x0c\x0d\x0a\x0b", (0x0A0B0C0D,)),
        (">Q", "little", b"\x01\x02\x0e\x0f\x0c\x0d\x0a\x0b", (0x0A0B0C0D0E0F0102,)),
        (
            ">HIQ",
            "little",
            b"\x01\x02\x07\x06\x09\x08\x01\x02\x0e\x0f\x0c\x0d\x0a\x0b",
            (0x0102, 0x09080706, 0x0A0B0C0D0E0F0102),
        ),
    ],
)
def test_unpack(
    format_str: str,
    word_order: Literal["little", "big"],
    data: bytes,
    expected_values: tuple[Any, ...],
) -> None:
    """Test unpacking data with different word orders."""
    s = WordOrderAwareStruct(format_str, word_order=word_order)
    result = s.unpack(data)
    assert result == expected_values


@pytest.mark.parametrize(
    ("format_str", "word_order", "values"),
    [
        (">H", "big", (0x1234,)),
        (">I", "little", (0x12345678,)),
        (">Q", "little", (0x0123456789ABCDEF,)),
        (">HIQ", "little", (0x1234, 0x56789ABC, 0x0123456789ABCDEF)),
        (">2I", "little", (0x11111111, 0x22222222)),
        (">4H", "big", (0x1111, 0x2222, 0x3333, 0x4444)),
    ],
)
def test_roundtrip(
    format_str: str,
    word_order: Literal["little", "big"],
    values: tuple[Any, ...],
) -> None:
    """Test that pack/unpack roundtrips correctly."""
    s = WordOrderAwareStruct(format_str, word_order=word_order)
    packed = s.pack(*values)
    unpacked = s.unpack(packed)
    assert unpacked == values


def test_unpack_from() -> None:
    """Test unpack_from with offset."""
    s = WordOrderAwareStruct(">I", word_order="big")
    data = b"\x00\x00\x0a\x0b\x0c\x0d\x00\x00"
    result = s.unpack_from(data, offset=2)
    assert result == (0x0A0B0C0D,)


def test_pack_into() -> None:
    """Test pack_into with buffer and offset."""
    s = WordOrderAwareStruct(">I", word_order="little")
    buffer = bytearray(8)
    s.pack_into(buffer, 2, 0x0A0B0C0D)
    assert buffer == b"\x00\x00\x0c\x0d\x0a\x0b\x00\x00"


@pytest.mark.parametrize(
    ("format_str", "expected_lengths"),
    [
        (">H", [2]),
        (">I", [4]),
        (">Q", [8]),
        (">2H", [2, 2]),
        (">HIQ", [2, 4, 8]),
        (">3I", [4, 4, 4]),
        (">HH2I", [2, 2, 4, 4]),
        (">10s", [10]),
        (">11sbHH", [11, 1, 2, 2]),
    ],
)
def test_parse_format_lengths(format_str: str, expected_lengths: list[int]) -> None:
    """Test parsing format string into value lengths."""
    result = WordOrderAwareStruct.parse_format_lengths(format_str)
    assert result == expected_lengths


def test_parse_format_with_different_endianness() -> None:
    """Test that parse_format_lengths handles byte order characters."""
    for prefix in ["@", "=", "<", ">", "!", ""]:
        result = WordOrderAwareStruct.parse_format_lengths(f"{prefix}HIQ")
        assert result == [2, 4, 8]


def test_size_property() -> None:
    """Test that size property works correctly."""
    assert WordOrderAwareStruct(">H").size == 2
    assert WordOrderAwareStruct(">I").size == 4
    assert WordOrderAwareStruct(">HIQ").size == 14


def test_value_lengths_only_set_for_little_endian() -> None:
    """Test that _value_lengths is only populated for little endian word order."""
    big_struct = WordOrderAwareStruct(">I", word_order="big")
    assert big_struct._value_lengths is None

    little_struct = WordOrderAwareStruct(">I", word_order="little")
    assert little_struct._value_lengths == [4]


def test_odd_length_values_in_swap() -> None:
    """Test struct with odd-length individual values (like 'b' padded to even)."""
    # Test a struct with byte values that need padding to reach even length
    # Use 'BB' (2 bytes total) with little endian word order
    s = WordOrderAwareStruct(">BB", word_order="little")
    result = s.pack(0x12, 0x34)
    assert result == b"\x12\x34"  # No swapping for single register
