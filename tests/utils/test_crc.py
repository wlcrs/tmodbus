from modbus_link.utils.crc import CRC16Modbus


def test_calculate_crc():
    """Test combined compute/check CRC."""
    data = b"\x12\x34\x23\x45\x34\x56\x45\x67"
    assert CRC16Modbus.calculate(data) == bytearray.fromhex("E2 DB")


def test_validate_crc():
    """Test framing with CRC."""
    assert CRC16Modbus.validate(b"\x01") is False

    data = b"\x12\x34\x23\x45\x34\x56\x45\x67\xe2\xdb"
    assert CRC16Modbus.validate(data)
