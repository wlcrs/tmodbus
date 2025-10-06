"""Tests for tmodbus/pdu/exception_status.py."""

import pytest
from tmodbus.const import FunctionCode
from tmodbus.pdu.exception_status import ReadExceptionStatusPDU


class TestReadExceptionStatusPDU:
    """Test suite for ReadExceptionStatus PDU."""

    def test_function_code(self) -> None:
        """Test that the function code is correctly set."""
        pdu = ReadExceptionStatusPDU()
        assert pdu.function_code == FunctionCode.READ_EXCEPTION_STATUS
        assert pdu.function_code == 0x07

    def test_encode_request(self) -> None:
        """Test encoding a Read Exception Status request."""
        pdu = ReadExceptionStatusPDU()
        encoded = pdu.encode_request()
        assert encoded == bytes([0x07])
        assert len(encoded) == 1

    def test_decode_request_valid(self) -> None:
        """Test decoding a valid Read Exception Status request."""
        data = bytes([0x07])
        pdu = ReadExceptionStatusPDU.decode_request(data)
        assert isinstance(pdu, ReadExceptionStatusPDU)
        assert pdu.function_code == 0x07

    def test_decode_request_invalid_length_too_short(self) -> None:
        """Test decoding fails when request is too short."""
        data = bytes([])
        with pytest.raises(ValueError, match=r"Invalid Read Exception Status request length: 0\. Expected 1\."):
            ReadExceptionStatusPDU.decode_request(data)

    def test_decode_request_invalid_length_too_long(self) -> None:
        """Test decoding fails when request is too long."""
        data = bytes([0x07, 0x00])
        with pytest.raises(ValueError, match=r"Invalid Read Exception Status request length: 2\. Expected 1\."):
            ReadExceptionStatusPDU.decode_request(data)

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decoding fails when function code is incorrect."""
        data = bytes([0x03])
        with pytest.raises(ValueError, match=r"Invalid function code: 0x03\. Expected 0x07\."):
            ReadExceptionStatusPDU.decode_request(data)

    def test_encode_response_valid_min(self) -> None:
        """Test encoding response with minimum status value (0)."""
        pdu = ReadExceptionStatusPDU()
        encoded = pdu.encode_response(0)
        assert encoded == bytes([0x07, 0x00])
        assert len(encoded) == 2

    def test_encode_response_valid_max(self) -> None:
        """Test encoding response with maximum status value (255)."""
        pdu = ReadExceptionStatusPDU()
        encoded = pdu.encode_response(255)
        assert encoded == bytes([0x07, 0xFF])
        assert len(encoded) == 2

    def test_encode_response_valid_middle(self) -> None:
        """Test encoding response with middle status value."""
        pdu = ReadExceptionStatusPDU()
        encoded = pdu.encode_response(0x55)
        assert encoded == bytes([0x07, 0x55])

    def test_encode_response_valid_all_bits_set(self) -> None:
        """Test encoding response with all bits set."""
        pdu = ReadExceptionStatusPDU()
        encoded = pdu.encode_response(0b11111111)
        assert encoded == bytes([0x07, 0xFF])

    def test_encode_response_valid_specific_bits(self) -> None:
        """Test encoding response with specific bit pattern."""
        pdu = ReadExceptionStatusPDU()
        encoded = pdu.encode_response(0b10101010)
        assert encoded == bytes([0x07, 0xAA])

    def test_encode_response_invalid_negative(self) -> None:
        """Test encoding fails with negative status value."""
        pdu = ReadExceptionStatusPDU()
        with pytest.raises(ValueError, match=r"Status -1 out of range \(0-255\)\."):
            pdu.encode_response(-1)

    def test_encode_response_invalid_too_high(self) -> None:
        """Test encoding fails with status value above 255."""
        pdu = ReadExceptionStatusPDU()
        with pytest.raises(ValueError, match=r"Status 256 out of range \(0-255\)\."):
            pdu.encode_response(256)

    def test_encode_response_invalid_much_too_high(self) -> None:
        """Test encoding fails with status value much higher than 255."""
        pdu = ReadExceptionStatusPDU()
        with pytest.raises(ValueError, match=r"Status 1000 out of range \(0-255\)\."):
            pdu.encode_response(1000)

    def test_decode_response_valid_min(self) -> None:
        """Test decoding response with minimum status value (0)."""
        pdu = ReadExceptionStatusPDU()
        data = bytes([0x07, 0x00])
        status = pdu.decode_response(data)
        assert status == 0

    def test_decode_response_valid_max(self) -> None:
        """Test decoding response with maximum status value (255)."""
        pdu = ReadExceptionStatusPDU()
        data = bytes([0x07, 0xFF])
        status = pdu.decode_response(data)
        assert status == 255

    def test_decode_response_valid_middle(self) -> None:
        """Test decoding response with middle status value."""
        pdu = ReadExceptionStatusPDU()
        data = bytes([0x07, 0x55])
        status = pdu.decode_response(data)
        assert status == 0x55

    def test_decode_response_valid_specific_bits(self) -> None:
        """Test decoding response with specific bit pattern."""
        pdu = ReadExceptionStatusPDU()
        data = bytes([0x07, 0xAA])
        status = pdu.decode_response(data)
        assert status == 0xAA

    def test_decode_response_invalid_length_too_short(self) -> None:
        """Test decoding fails when response is too short."""
        pdu = ReadExceptionStatusPDU()
        data = bytes([0x07])
        with pytest.raises(ValueError, match=r"Invalid Read Exception Status response length: 1\. Expected 2\."):
            pdu.decode_response(data)

    def test_decode_response_invalid_length_empty(self) -> None:
        """Test decoding fails when response is empty."""
        pdu = ReadExceptionStatusPDU()
        data = bytes([])
        with pytest.raises(ValueError, match=r"Invalid Read Exception Status response length: 0\. Expected 2\."):
            pdu.decode_response(data)

    def test_decode_response_invalid_length_too_long(self) -> None:
        """Test decoding fails when response is too long."""
        pdu = ReadExceptionStatusPDU()
        data = bytes([0x07, 0x55, 0x00])
        with pytest.raises(ValueError, match=r"Invalid Read Exception Status response length: 3\. Expected 2\."):
            pdu.decode_response(data)

    def test_decode_response_invalid_function_code(self) -> None:
        """Test decoding fails when function code is incorrect."""
        pdu = ReadExceptionStatusPDU()
        data = bytes([0x03, 0x55])
        with pytest.raises(ValueError, match=r"Invalid function code: 0x03\. Expected 0x07\."):
            pdu.decode_response(data)

    def test_round_trip_encode_decode_request(self) -> None:
        """Test that encoding and decoding a request is symmetric."""
        pdu = ReadExceptionStatusPDU()
        encoded = pdu.encode_request()
        decoded = ReadExceptionStatusPDU.decode_request(encoded)
        assert decoded.function_code == pdu.function_code

    def test_round_trip_encode_decode_response_min(self) -> None:
        """Test round-trip encode/decode for minimum status value."""
        pdu = ReadExceptionStatusPDU()
        status = 0
        encoded = pdu.encode_response(status)
        decoded = pdu.decode_response(encoded)
        assert decoded == status

    def test_round_trip_encode_decode_response_max(self) -> None:
        """Test round-trip encode/decode for maximum status value."""
        pdu = ReadExceptionStatusPDU()
        status = 255
        encoded = pdu.encode_response(status)
        decoded = pdu.decode_response(encoded)
        assert decoded == status

    @pytest.mark.parametrize(
        "status",
        [
            0,
            1,
            2,
            15,
            16,
            127,
            128,
            170,  # 0xAA
            204,  # 0xCC
            240,  # 0xF0
            254,
            255,
        ],
    )
    def test_round_trip_various_status_values(self, status: int) -> None:
        """Test round-trip encode/decode for various status values."""
        pdu = ReadExceptionStatusPDU()
        encoded = pdu.encode_response(status)
        decoded = pdu.decode_response(encoded)
        assert decoded == status

    def test_encode_decode_all_possible_status_values(self) -> None:
        """Test encode/decode for all possible status values (0-255)."""
        pdu = ReadExceptionStatusPDU()
        for status in range(256):
            encoded = pdu.encode_response(status)
            decoded = pdu.decode_response(encoded)
            assert decoded == status, f"Failed for status {status}"

    def test_response_data_length_property(self) -> None:
        """Test that response data has correct length."""
        pdu = ReadExceptionStatusPDU()
        for status in [0, 127, 255]:
            encoded = pdu.encode_response(status)
            assert len(encoded) == 2

    def test_request_data_length_property(self) -> None:
        """Test that request data has correct length."""
        pdu = ReadExceptionStatusPDU()
        encoded = pdu.encode_request()
        assert len(encoded) == 1
