"""Tests for tmodbus/pdu/serial_line.py ."""

import struct

import pytest
from tmodbus.exceptions import InvalidRequestError, InvalidResponseError
from tmodbus.pdu.serial_line import ID_OFF, ID_ON, ReportServerIdPDU, ServerIdResponse


def make_response(
    function_code: int, server_id: bytes, run_indicator_status: int, additional_data: bytes = b""
) -> bytes:
    """Construct a valid ReportServerIdPDU response byte string.

    Args:
        function_code: The Modbus function code (int)
        server_id: The server ID as bytes
        run_indicator_status: Status byte (ID_ON or ID_OFF)
        additional_data: Any additional data as bytes
    Returns:
        Bytes representing a valid response for ReportServerIdPDU

    """
    byte_count = len(server_id) + 1 + len(additional_data)
    return bytes([function_code, byte_count]) + server_id + bytes([run_indicator_status]) + additional_data


def test_encode_request() -> None:
    """Test that ReportServerIdPDU.encode_request returns the correct function code byte."""
    pdu = ReportServerIdPDU()
    assert pdu.encode_request() == bytes([pdu.function_code])


def test_decode_response_valid() -> None:
    """Test decode_response parses valid responses with both ON and OFF status and additional data."""
    pdu = ReportServerIdPDU()
    server_id = b"abc"
    additional = b"xyz"
    response = make_response(pdu.function_code, server_id, ID_ON, additional)
    result = pdu.decode_response(response)
    assert result.server_id == server_id
    assert result.run_indicator_status is True
    assert result.additional_data == additional

    response = make_response(pdu.function_code, server_id, ID_OFF, b"")
    result = pdu.decode_response(response)
    assert result.server_id == server_id
    assert result.run_indicator_status is False
    assert result.additional_data == b""


def test_decode_response_invalid_function_code() -> None:
    """Test decode_response raises InvalidResponseError if the function code is not correct."""
    pdu = ReportServerIdPDU()
    response = make_response(0x12, b"abc", ID_ON, b"")
    with pytest.raises(InvalidResponseError, match="Invalid function code"):
        pdu.decode_response(response)


def test_decode_response_invalid_length() -> None:
    """Test decode_response raises InvalidResponseError if the response is too short for the byte count."""
    pdu = ReportServerIdPDU()
    # byte_count too large
    response = bytes([pdu.function_code, 10]) + b"a" * 3
    with pytest.raises(InvalidResponseError, match="Response length"):
        pdu.decode_response(response)


def test_decode_response_missing_status() -> None:
    """Test decode_response raises InvalidResponseError if no status byte (ID_ON/ID_OFF) is present."""
    pdu = ReportServerIdPDU()
    # No status byte (neither ID_ON nor ID_OFF)
    response = bytes([pdu.function_code, 3]) + b"abc"
    with pytest.raises(InvalidResponseError, match="Run indicator status byte not found"):
        pdu.decode_response(response)


def test_decode_response_struct_error() -> None:
    """Test decode_response raises InvalidResponseError on struct.error (malformed response).

    Covers the struct.error branch for unpacking.
    """
    pdu = ReportServerIdPDU()
    # Too short to unpack two bytes
    response = b"\x11"
    with pytest.raises(
        InvalidResponseError, match="Expected response to start with function code and byte count"
    ) as excinfo:
        pdu.decode_response(response)
    # Optionally check that the cause is struct.error
    assert isinstance(excinfo.value.__cause__, struct.error)


def test_decode_request_valid() -> None:
    """Test decode_request accepts a valid single-byte request and returns the same PDU instance."""
    data = bytes([0x11])
    assert ReportServerIdPDU.decode_request(data)


def test_decode_request_invalid_length() -> None:
    """Test decode_request raises InvalidRequestError if the request is longer than one byte."""
    data = bytes([0x11, 0x01])
    with pytest.raises(InvalidRequestError, match="Expected request with only function code"):
        ReportServerIdPDU.decode_request(data)


def test_decode_request_invalid_function_code() -> None:
    """Test decode_request raises InvalidRequestError if the function code is not correct."""
    data = bytes([0x12])
    with pytest.raises(InvalidRequestError, match="Invalid function code"):
        ReportServerIdPDU.decode_request(data)


def test_encode_response() -> None:
    """Test encode_response produces the correct bytes for ON/OFF status and additional data."""
    pdu = ReportServerIdPDU()
    value = ServerIdResponse(server_id=b"abc", run_indicator_status=True, additional_data=b"xyz")
    encoded = pdu.encode_response(value)
    # Should match the make_response helper
    expected = make_response(pdu.function_code, b"abc", ID_ON, b"xyz")
    assert encoded == expected

    value = ServerIdResponse(server_id=b"", run_indicator_status=False, additional_data=b"")
    encoded = pdu.encode_response(value)
    expected = make_response(pdu.function_code, b"", ID_OFF, b"")
    assert encoded == expected
