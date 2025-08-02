import struct

import pytest

from modbus_link.exceptions import InvalidResponseError
from modbus_link.pdu import ReadCoilsPDU, WriteMultipleCoilsPDU, WriteSingleCoilPDU


def test_read_coils_quantity_validation():
    """Test validation of quantity in Read Coils PDU."""
    with pytest.raises(ValueError, match="Quantity must be between 1 and 2000."):
        ReadCoilsPDU(start_address=1, quantity=0)
    with pytest.raises(ValueError, match="Quantity must be between 1 and 2000."):
        ReadCoilsPDU(start_address=1, quantity=2001)


def test_read_coils_encode_request():
    """Test encoding of Read Coils PDU."""
    pdu = ReadCoilsPDU(start_address=1, quantity=10)
    expected_bytes = struct.pack(">BHH", 0x01, 1, 10)

    assert pdu.encode_request() == expected_bytes


def test_read_coils_decode_response():
    """Test decoding of Read Coils PDU."""
    pdu = ReadCoilsPDU(start_address=1, quantity=1)
    response_bytes = bytearray.fromhex("01 01 01")
    assert pdu.decode_response(response_bytes) == [True]

    pdu = ReadCoilsPDU(start_address=2, quantity=3)
    assert pdu.decode_response(bytearray.fromhex("01 01 04")) == [False, False, True]
    assert pdu.decode_response(bytearray.fromhex("01 01 05")) == [True, False, True]


def test_read_coils_invalid_response():
    """Test invalid response handling in Read Coils PDU."""
    pdu = ReadCoilsPDU(start_address=1, quantity=5)

    with pytest.raises(InvalidResponseError, match="Expected response to start with function code and byte count"):
        pdu.decode_response(bytearray.fromhex("FF"))

    # Invalid function code
    with pytest.raises(InvalidResponseError, match="Invalid function code: expected 01, received 02"):
        pdu.decode_response(bytearray.fromhex("02 01 05"))

    # Invalid length
    with pytest.raises(InvalidResponseError, match="Invalid response PDU length: expected 10, got 5"):
        pdu.decode_response(bytearray.fromhex("01 08 02 03 04"))

    # Invalid byte count
    with pytest.raises(InvalidResponseError, match="Invalid byte count: expected 1, got 8"):
        pdu.decode_response(bytearray.fromhex("01 08 02 03 04 05 FF FF FF FF"))


def test_write_single_coil_pdu():
    """Test Write Single Coil PDU."""

    pdu = WriteSingleCoilPDU(address=1, value=True)
    assert pdu.encode_request() == bytearray.fromhex("05 00 01 FF 00")

    pdu = WriteSingleCoilPDU(address=12345, value=False)
    assert pdu.encode_request() == bytearray.fromhex("05 30 39 00 00")


def test_write_single_coil_decode_response():
    """Test decoding of Write Single Coil PDU."""
    pdu = WriteSingleCoilPDU(address=1, value=True)
    response_bytes = bytearray.fromhex("05 00 01 FF 00")
    assert pdu.decode_response(response_bytes) is None

    with pytest.raises(InvalidResponseError, match="Expected response to match request"):
        pdu.decode_response(bytearray.fromhex("06 00 01 FF 00"))

    pdu = WriteSingleCoilPDU(address=12345, value=False)
    response_bytes = bytearray.fromhex("05 30 39 00 00")
    assert pdu.decode_response(response_bytes) is None

    with pytest.raises(InvalidResponseError, match="Expected response to match request"):
        pdu.decode_response(bytearray.fromhex("06 30 39 00 00"))

    with pytest.raises(InvalidResponseError, match="Expected response to match request"):
        pdu.decode_response(bytearray.fromhex("05 30 40 00 00"))


def test_write_multiple_coils_validation():
    """Test validation of Write Multiple Coils PDU."""
    with pytest.raises(ValueError, match="Address must be between 0 and 65535."):
        WriteMultipleCoilsPDU(start_address=-1, values=[True])
    with pytest.raises(ValueError, match="Address must be between 0 and 65535."):
        WriteMultipleCoilsPDU(start_address=65536, values=[True])
    with pytest.raises(ValueError, match="Number of coils must be between 1 and 1968."):
        WriteMultipleCoilsPDU(start_address=1, values=[True] * 1969)


@pytest.mark.parametrize(
    "start_address, values, expected_bytes",
    [
        (10, [True, False, True], bytearray.fromhex("0F 00 0A 00 03 01 05")),
        (12345, [False] * 16, bytearray.fromhex("0F 30 39 00 10 02 00 00")),
        (12345, [True] * 19, bytearray.fromhex("0F 30 39 00 13 03 FF FF 07")),
        (1, [True] * 5, bytearray.fromhex("0F 00 01 00 05 01 1F")),
        (1, [True], bytearray.fromhex("0F 00 01 00 01 01 01")),
    ],
)
def test_write_multiple_coils_encode_request(start_address, values, expected_bytes):
    """Test encoding of Write Multiple Coils PDU."""
    pdu = WriteMultipleCoilsPDU(start_address=start_address, values=values)
    assert pdu.encode_request() == expected_bytes


@pytest.mark.parametrize(
    "response, address, value_count",
    [
        (bytearray.fromhex("0F 00 0A 00 07"), 10, 7),
        (bytearray.fromhex("0F 30 39 00 10"), 12345, 16),
        (bytearray.fromhex("0F 30 39 00 13"), 12345, 19),
        (bytearray.fromhex("0F 00 01 00 05"), 1, 5),
        (bytearray.fromhex("0F 00 01 00 01"), 1, 1),
    ],
)
def test_write_multiple_coils_decode_response(response, address, value_count):
    """Test decoding of Write Multiple Coils PDU."""
    pdu = WriteMultipleCoilsPDU(start_address=address, values=[True] * value_count)
    assert pdu.decode_response(response) is None

    invalid_pdu = WriteMultipleCoilsPDU(start_address=address, values=[False] * (value_count + 1))
    with pytest.raises(InvalidResponseError, match="Device response does not match request"):
        invalid_pdu.decode_response(response)
