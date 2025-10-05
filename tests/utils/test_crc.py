"""Tests for tmodbus/utils/crc.py ."""

from tmodbus.utils.crc import calculate_crc16, validate_crc16


def test_calculate_crc() -> None:
    """Test combined compute/check CRC."""
    data = b"\x12\x34\x23\x45\x34\x56\x45\x67"
    assert calculate_crc16(data) == bytearray.fromhex("E2 DB")


def test_validate_crc() -> None:
    """Test framing with CRC."""
    assert validate_crc16(b"\x01") is False

    data = b"\x12\x34\x23\x45\x34\x56\x45\x67\xe2\xdb"
    assert validate_crc16(data)
