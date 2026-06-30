"""Tests for tmodbus/utils/crc.py ."""

import pytest
from tmodbus.utils.crc import calculate_crc16, validate_crc16


def _reference_crc16(data: bytes) -> bytes:
    """Independent bit-by-bit CRC16 reference for polynomial 0xA001."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 0x0001 else crc >> 1
    return crc.to_bytes(2, byteorder="little")


def test_calculate_crc() -> None:
    """Test combined compute/check CRC."""
    data = b"\x12\x34\x23\x45\x34\x56\x45\x67"
    assert calculate_crc16(data) == bytearray.fromhex("E2 DB")


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00",
        b"\xff",
        b"\x01\x03\x00\x00\x00\x01",
        bytes(range(256)),
        b"\xff" * 256,
    ],
)
def test_calculate_crc_matches_reference(data: bytes) -> None:
    """The table-driven implementation must match a bit-by-bit reference."""
    assert calculate_crc16(data) == _reference_crc16(data)


def test_validate_crc() -> None:
    """Test framing with CRC."""
    assert validate_crc16(b"\x01") is False

    data = b"\x12\x34\x23\x45\x34\x56\x45\x67\xe2\xdb"
    assert validate_crc16(data)
