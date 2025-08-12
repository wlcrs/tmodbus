import pytest

from tmodbus.exceptions import InvalidResponseError
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteMultipleRegistersPDU, WriteSingleRegisterPDU


def test_read_holding_registers_quantity_validation():
    """Test validation of quantity in Read Holding Registers PDU."""
    with pytest.raises(ValueError, match="Quantity must be between 1 and 125."):
        ReadHoldingRegistersPDU(start_address=1, quantity=0)
    with pytest.raises(ValueError, match="Quantity must be between 1 and 125."):
        ReadHoldingRegistersPDU(start_address=1, quantity=126)


def test_read_holding_registers_encode_request():
    """Test encoding of Read Holding Registers PDU."""
    pdu = ReadHoldingRegistersPDU(start_address=1, quantity=10)
    assert pdu.encode_request() == bytearray.fromhex("03 00 01 00 0A")


def test_read_holding_registers_decode_response():
    """Test decoding of Read Holding Registers PDU."""
    pdu = ReadHoldingRegistersPDU(start_address=1, quantity=2)
    response_bytes = bytearray.fromhex("03 04 00 01 00 02")
    assert pdu.decode_response(response_bytes) == [1, 2]

    # Test with more registers
    pdu = ReadHoldingRegistersPDU(start_address=2, quantity=3)
    response_bytes = bytearray.fromhex("03 06 00 03 00 04 00 05")
    assert pdu.decode_response(response_bytes) == [3, 4, 5]


def test_read_holding_registers_invalid_response():
    """Test invalid response handling in Read Holding Registers PDU."""
    pdu = ReadHoldingRegistersPDU(start_address=1, quantity=5)

    with pytest.raises(InvalidResponseError, match="Expected response to start with function code and byte count"):
        pdu.decode_response(bytearray.fromhex("FF"))

    # Invalid function code
    with pytest.raises(InvalidResponseError, match="Invalid function code: expected 03, received 04"):
        pdu.decode_response(bytearray.fromhex("04 01 05"))

    # Invalid length
    with pytest.raises(InvalidResponseError, match="Invalid response PDU length: expected 10, got 5"):
        pdu.decode_response(bytearray.fromhex("03 08 02 03 04"))

    # Invalid register count
    with pytest.raises(InvalidResponseError, match="Invalid register count: expected 5, got 4"):
        pdu.decode_response(bytearray.fromhex("03 08 02 03 04 05 FF FF FF FF"))


def test_write_single_register_validation():
    """Test validation of Write Single Register PDU."""
    with pytest.raises(ValueError, match="Address must be between 0 and 65535."):
        WriteSingleRegisterPDU(address=-1, value=123)
    with pytest.raises(ValueError, match="Address must be between 0 and 65535."):
        WriteSingleRegisterPDU(address=65536, value=123)
    with pytest.raises(ValueError, match="Value must be between 0 and 65535."):
        WriteSingleRegisterPDU(address=1, value=-1)
    with pytest.raises(ValueError, match="Value must be between 0 and 65535."):
        WriteSingleRegisterPDU(address=1, value=65536)


def test_write_single_register_encode_request():
    """Test encoding of Write Single Register PDU."""
    pdu = WriteSingleRegisterPDU(address=1, value=12345)
    assert pdu.encode_request() == bytearray.fromhex("06 00 01 30 39")


def test_write_single_register_decode_response():
    """Test decoding of Write Single Register PDU."""
    pdu = WriteSingleRegisterPDU(address=1, value=12345)
    response_bytes = bytearray.fromhex("06 00 01 30 39")
    assert pdu.decode_response(response_bytes) == 12345

    with pytest.raises(InvalidResponseError, match="Expected response to match request"):
        pdu.decode_response(bytearray.fromhex("07 00 01 30 39"))


def test_write_multiple_registers_validation():
    """Test validation of Write Multiple Registers PDU."""
    with pytest.raises(ValueError, match="Address must be between 0 and 65535."):
        WriteMultipleRegistersPDU(start_address=-1, values=[123])
    with pytest.raises(ValueError, match="Address must be between 0 and 65535."):
        WriteMultipleRegistersPDU(start_address=65536, values=[123])
    with pytest.raises(ValueError, match="Number of registers must be between 1 and 123."):
        WriteMultipleRegistersPDU(start_address=1, values=[123] * 124)

    with pytest.raises(ValueError, match="Value must be between 0 and 65535: 70000"):
        WriteMultipleRegistersPDU(start_address=1, values=[70000])


def test_write_multiple_registers_encode_request():
    """Test encoding of Write Multiple Registers PDU."""
    pdu = WriteMultipleRegistersPDU(start_address=1, values=[12345, 255])
    assert pdu.encode_request() == bytearray.fromhex("10 00 01 00 02 04 30 39 00 FF")


def test_write_multiple_registers_decode_response():
    """Test decoding of Write Multiple Registers PDU."""
    pdu = WriteMultipleRegistersPDU(start_address=1, values=[12345, 255])
    response_bytes = bytearray.fromhex("10 00 01 00 02")
    assert pdu.decode_response(response_bytes) == 2

    with pytest.raises(InvalidResponseError, match="Device response does not match request"):
        pdu.decode_response(bytearray.fromhex("11 00 01 00 02"))
