"""Tests for tmodbus/utils/lrc.py."""

from tmodbus.utils.lrc import calculate_lrc, validate_lrc


def test_calculate_lrc_simple() -> None:
    """Test LRC calculation with simple data."""
    # Example from Modbus ASCII spec
    # Message: 01 03 00 00 00 64
    data = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x64])
    lrc = calculate_lrc(data)
    # LRC = -(01 + 03 + 00 + 00 + 00 + 64) = -68 = 0xBC (two's complement)
    assert lrc == 0x98


def test_calculate_lrc_empty() -> None:
    """Test LRC calculation with empty data."""
    assert calculate_lrc(b"") == 0x00


def test_calculate_lrc_single_byte() -> None:
    """Test LRC calculation with single byte."""
    assert calculate_lrc(b"\x01") == 0xFF


def test_validate_lrc_valid() -> None:
    """Test LRC validation with valid LRC."""
    data = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x64])
    lrc = calculate_lrc(data)
    assert validate_lrc(data, lrc)


def test_validate_lrc_invalid() -> None:
    """Test LRC validation with invalid LRC."""
    data = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x64])
    assert not validate_lrc(data, 0x00)


def test_lrc_roundtrip() -> None:
    """Test that LRC calculation and validation work together."""
    test_data = [
        b"\x01\x03\x00\x00\x00\x64",
        b"\x11\x06\x00\x01\x00\x03",
        b"\xff\xff\xff\xff",
        b"\x00\x00\x00\x00",
    ]
    for data in test_data:
        lrc = calculate_lrc(data)
        assert validate_lrc(data, lrc), f"LRC validation failed for {data.hex()}"
