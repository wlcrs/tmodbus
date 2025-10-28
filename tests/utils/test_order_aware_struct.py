"""Tests for word_aware_struct module."""

import struct
from typing import Any, Literal

import pytest
from tmodbus.utils.order_aware_struct import OrderAwareStruct


def test_init_odd_size_raises() -> None:
    """Test that odd-sized structs raise ValueError."""
    with pytest.raises(ValueError, match="multiple of 2 bytes"):
        OrderAwareStruct(">b")  # 1 byte


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
    s = OrderAwareStruct(format_str, word_order=word_order)
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
    s = OrderAwareStruct(format_str, word_order=word_order)
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
    s = OrderAwareStruct(format_str, word_order=word_order)
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
    s = OrderAwareStruct(format_str, word_order=word_order)
    packed = s.pack(*values)
    unpacked = s.unpack(packed)
    assert unpacked == values


def test_unpack_from() -> None:
    """Test unpack_from with offset."""
    s = OrderAwareStruct(">I", word_order="big")
    data = b"\x00\x00\x0a\x0b\x0c\x0d\x00\x00"
    result = s.unpack_from(data, offset=2)
    assert result == (0x0A0B0C0D,)


def test_pack_into() -> None:
    """Test pack_into with buffer and offset."""
    s = OrderAwareStruct(">I", word_order="little")
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
    result = OrderAwareStruct.parse_format_lengths(format_str)
    assert result == expected_lengths


def test_parse_format_with_different_endianness() -> None:
    """Test that parse_format_lengths handles byte order characters."""
    for prefix in ["@", "=", "<", ">", "!", ""]:
        result = OrderAwareStruct.parse_format_lengths(f"{prefix}HIQ")
        assert result == [2, 4, 8]


def test_size_property() -> None:
    """Test that size property works correctly."""
    assert OrderAwareStruct(">H").size == 2
    assert OrderAwareStruct(">I").size == 4
    assert OrderAwareStruct(">HIQ").size == 14


def test_value_lengths_only_set_for_little_endian() -> None:
    """Test that _value_lengths is only populated for little endian word order."""
    big_struct = OrderAwareStruct(">I", word_order="big")
    assert big_struct._value_lengths is None

    little_struct = OrderAwareStruct(">I", word_order="little")
    assert little_struct._value_lengths == [4]


def test_odd_length_values_in_swap() -> None:
    """Test struct with odd-length individual values (like 'b' padded to even)."""
    # Test a struct with byte values that need padding to reach even length
    # Use 'BB' (2 bytes total) with little endian word order
    s = OrderAwareStruct(">BB", word_order="little")
    result = s.pack(0x12, 0x34)
    assert result == b"\x12\x34"  # No swapping for single register


# Byte order tests


@pytest.mark.parametrize(
    ("word_order", "byte_order", "value", "expected_bytes"),
    [
        # 32-bit value (4 bytes): 0x0A0B0C0D
        # ABCD: word_order="big", byte_order="big"
        ("big", "big", 0x0A0B0C0D, b"\x0a\x0b\x0c\x0d"),
        # BADC: word_order="big", byte_order="little"
        ("big", "little", 0x0A0B0C0D, b"\x0b\x0a\x0d\x0c"),
        # CDAB: word_order="little", byte_order="big"
        ("little", "big", 0x0A0B0C0D, b"\x0c\x0d\x0a\x0b"),
        # DCBA: word_order="little", byte_order="little"
        ("little", "little", 0x0A0B0C0D, b"\x0d\x0c\x0b\x0a"),
    ],
)
def test_byte_order_32bit(
    word_order: Literal["big", "little"],
    byte_order: Literal["big", "little"],
    value: int,
    expected_bytes: bytes,
) -> None:
    """Test different byte orders for 32-bit values."""
    s = OrderAwareStruct(">I", word_order=word_order, byte_order=byte_order)
    result = s.pack(value)
    assert result == expected_bytes
    # Verify roundtrip
    unpacked = s.unpack(result)
    assert unpacked[0] == value


@pytest.mark.parametrize(
    ("word_order", "byte_order", "value", "expected_bytes"),
    [
        # 64-bit value (8 bytes): 0x0102030405060708
        # ABCD: word_order="big", byte_order="big"
        ("big", "big", 0x0102030405060708, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
        # BADC: word_order="big", byte_order="little"
        ("big", "little", 0x0102030405060708, b"\x02\x01\x04\x03\x06\x05\x08\x07"),
        # CDAB: word_order="little", byte_order="big"
        ("little", "big", 0x0102030405060708, b"\x07\x08\x05\x06\x03\x04\x01\x02"),
        # DCBA: word_order="little", byte_order="little"
        ("little", "little", 0x0102030405060708, b"\x08\x07\x06\x05\x04\x03\x02\x01"),
    ],
)
def test_byte_order_64bit(
    word_order: Literal["big", "little"],
    byte_order: Literal["big", "little"],
    value: int,
    expected_bytes: bytes,
) -> None:
    """Test different byte orders for 64-bit values."""
    s = OrderAwareStruct(">Q", word_order=word_order, byte_order=byte_order)
    result = s.pack(value)
    assert result == expected_bytes
    # Verify roundtrip
    unpacked = s.unpack(result)
    assert unpacked[0] == value


def test_byte_order_float32() -> None:
    """Test byte order with 32-bit float."""
    # Float value: 1.0 = 0x3F800000 in IEEE 754
    value = 1.0

    # ABCD: word_order="big", byte_order="big"
    s_abcd = OrderAwareStruct(">f", word_order="big", byte_order="big")
    packed_abcd = s_abcd.pack(value)
    assert packed_abcd == b"\x3f\x80\x00\x00"
    assert s_abcd.unpack(packed_abcd)[0] == value

    # BADC: word_order="big", byte_order="little"
    s_badc = OrderAwareStruct(">f", word_order="big", byte_order="little")
    packed_badc = s_badc.pack(value)
    assert packed_badc == b"\x80\x3f\x00\x00"
    assert s_badc.unpack(packed_badc)[0] == value

    # CDAB: word_order="little", byte_order="big"
    s_cdab = OrderAwareStruct(">f", word_order="little", byte_order="big")
    packed_cdab = s_cdab.pack(value)
    assert packed_cdab == b"\x00\x00\x3f\x80"
    assert s_cdab.unpack(packed_cdab)[0] == value

    # DCBA: word_order="little", byte_order="little"
    s_dcba = OrderAwareStruct(">f", word_order="little", byte_order="little")
    packed_dcba = s_dcba.pack(value)
    assert packed_dcba == b"\x00\x00\x80\x3f"
    assert s_dcba.unpack(packed_dcba)[0] == value


def test_byte_order_double() -> None:
    """Test byte order with 64-bit double."""
    # Double value: 1.0 = 0x3FF0000000000000 in IEEE 754
    value = 1.0

    # ABCD: word_order="big", byte_order="big"
    s_abcd = OrderAwareStruct(">d", word_order="big", byte_order="big")
    packed_abcd = s_abcd.pack(value)
    assert packed_abcd == b"\x3f\xf0\x00\x00\x00\x00\x00\x00"
    assert s_abcd.unpack(packed_abcd)[0] == value

    # DCBA: word_order="little", byte_order="little"
    s_dcba = OrderAwareStruct(">d", word_order="little", byte_order="little")
    packed_dcba = s_dcba.pack(value)
    assert packed_dcba == b"\x00\x00\x00\x00\x00\x00\xf0\x3f"
    assert s_dcba.unpack(packed_dcba)[0] == value


def test_byte_order_multiple_values() -> None:
    """Test byte order with multiple values in one struct."""
    # Mix of H (2 bytes), I (4 bytes)
    # ABCD: word_order="big", byte_order="big"
    s_abcd = OrderAwareStruct(">HI", word_order="big", byte_order="big")
    packed_abcd = s_abcd.pack(0x0102, 0x0A0B0C0D)
    assert packed_abcd == b"\x01\x02\x0a\x0b\x0c\x0d"

    # CDAB: word_order="little", byte_order="big"
    s_cdab = OrderAwareStruct(">HI", word_order="little", byte_order="big")
    packed_cdab = s_cdab.pack(0x0102, 0x0A0B0C0D)
    assert packed_cdab == b"\x01\x02\x0c\x0d\x0a\x0b"

    # DCBA: word_order="little", byte_order="little"
    s_dcba = OrderAwareStruct(">HI", word_order="little", byte_order="little")
    packed_dcba = s_dcba.pack(0x0102, 0x0A0B0C0D)
    assert packed_dcba == b"\x01\x02\x0d\x0c\x0b\x0a"


def test_byte_order_16bit_no_effect() -> None:
    """Test that byte order has no effect on single-register (16-bit) values."""
    # For 16-bit values, byte order should have no effect since they fit in one register
    value = 0x0102
    # All byte order combinations should produce the same result for single-register values
    for word_order in ["big", "little"]:
        for byte_order in ["big", "little"]:
            s = OrderAwareStruct(">H", word_order=word_order, byte_order=byte_order)  # type: ignore[arg-type]
            assert s.pack(value) == b"\x01\x02"


def test_byte_order_backwards_compatibility_with_word_order() -> None:
    """Test that word_order parameter still works for backwards compatibility."""
    # word_order="little", byte_order="big" produces CDAB
    s_word_little = OrderAwareStruct(">I", word_order="little", byte_order="big")

    value = 0x0A0B0C0D
    assert s_word_little.pack(value) == b"\x0c\x0d\x0a\x0b"

    # word_order="big", byte_order="big" produces ABCD (standard)
    s_word_big = OrderAwareStruct(">I", word_order="big", byte_order="big")

    assert s_word_big.pack(value) == b"\x0a\x0b\x0c\x0d"


def test_byte_order_value_lengths_set_correctly() -> None:
    """Test that _value_lengths is set correctly based on byte_order and word_order."""
    # ABCD (word_order="big", byte_order="big") should not set _value_lengths
    s_abcd = OrderAwareStruct(">I", word_order="big", byte_order="big")
    assert s_abcd._value_lengths is None

    # Other combinations should set _value_lengths
    for word_order, byte_order in [("big", "little"), ("little", "big"), ("little", "little")]:
        s = OrderAwareStruct(">I", word_order=word_order, byte_order=byte_order)  # type: ignore[arg-type]
        assert s._value_lengths == [4]


def test_byte_order_complex_struct() -> None:
    """Test byte order with complex struct containing multiple value types."""
    # H (2 bytes) + I (4 bytes) + Q (8 bytes)
    format_str = ">HIQ"

    # ABCD: word_order="big", byte_order="big"
    s_abcd = OrderAwareStruct(format_str, word_order="big", byte_order="big")
    # DCBA: word_order="little", byte_order="little"
    s_dcba = OrderAwareStruct(format_str, word_order="little", byte_order="little")

    values = (0x0102, 0x03040506, 0x0708090A0B0C0D0E)

    # ABCD: no transformation
    packed_abcd = s_abcd.pack(*values)
    expected_abcd = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e"
    assert packed_abcd == expected_abcd

    # DCBA: full reversal for multi-byte values
    packed_dcba = s_dcba.pack(*values)
    # H stays same (2 bytes): \x01\x02
    # I reversed: 0x03040506 -> \x06\x05\x04\x03
    # Q reversed: 0x0708090A0B0C0D0E -> \x0e\x0d\x0c\x0b\x0a\x09\x08\x07
    expected_dcba = b"\x01\x02\x06\x05\x04\x03\x0e\x0d\x0c\x0b\x0a\x09\x08\x07"
    assert packed_dcba == expected_dcba

    # Verify roundtrip
    assert s_abcd.unpack(packed_abcd) == values
    assert s_dcba.unpack(packed_dcba) == values


def test_apply_byte_order_abcd_passthrough() -> None:
    """Test that _apply_byte_order with word_order='big', byte_order='big' returns data unchanged."""
    # This tests line 187: the ABCD early return path
    test_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    result = OrderAwareStruct._apply_byte_order(test_data, word_order="big", byte_order="big")
    assert result == test_data


def test_apply_byte_order_invalid_combination() -> None:
    """Test that _apply_byte_order raises ValueError for invalid parameter combinations."""
    # This tests lines 210-211: the ValueError for unknown combinations
    test_data = b"\x01\x02\x03\x04"

    # Test with invalid word_order (note: type system would catch this, but testing runtime)
    with pytest.raises(ValueError, match="Unknown combination"):
        OrderAwareStruct._apply_byte_order(
            test_data,
            word_order="invalid",  # type: ignore[arg-type]
            byte_order="big",
        )

    # Test with invalid byte_order
    with pytest.raises(ValueError, match="Unknown combination"):
        OrderAwareStruct._apply_byte_order(
            test_data,
            word_order="big",
            byte_order="invalid",  # type: ignore[arg-type]
        )

    # Test with both invalid
    with pytest.raises(ValueError, match="Unknown combination"):
        OrderAwareStruct._apply_byte_order(
            test_data,
            word_order="invalid",  # type: ignore[arg-type]
            byte_order="invalid",  # type: ignore[arg-type]
        )
