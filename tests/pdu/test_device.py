"""Tests for device.py - Read Device Identification PDU."""

import logging
import struct

import pytest
from tmodbus.pdu.device import (
    ConformityLevel,
    ReadDeviceIdentificationPDU,
)


class TestReadDeviceIdentificationPDU:
    """Test ReadDeviceIdentificationPDU class."""

    def test_init_valid(self) -> None:
        """Test creating a valid ReadDeviceIdentificationPDU."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)
        assert pdu.read_device_id_code == 0x01
        assert pdu.object_id == 0x00

    def test_init_invalid_object_id_negative(self) -> None:
        """Test creating ReadDeviceIdentificationPDU with negative object_id."""
        with pytest.raises(ValueError, match=r"Object ID must be between 0x00 and 0xFF\."):
            ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=-1)

    def test_init_invalid_object_id_too_high(self) -> None:
        """Test creating ReadDeviceIdentificationPDU with object_id >= 0xFF."""
        with pytest.raises(ValueError, match=r"Object ID must be between 0x00 and 0xFF\."):
            ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0xFF)

    def test_encode_request(self) -> None:
        """Test encoding request."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)
        encoded = pdu.encode_request()
        # Function code (0x2B) + Sub-function (0x0E) + Read Device ID Code (0x01) + Object ID (0x00)
        assert encoded == b"\x2b\x0e\x01\x00"

    def test_encode_request_different_values(self) -> None:
        """Test encoding request with different values."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x04, object_id=0x05)
        encoded = pdu.encode_request()
        assert encoded == b"\x2b\x0e\x04\x05"

    def test_decode_response_basic(self) -> None:
        """Test decoding a basic response."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)

        # Build response: FC + SubFC + DeviceIDCode + ConformityLevel + More + NextObjID + NumObjects + Objects
        response = struct.pack(
            ">BBBBBBB",
            0x2B,  # Function code
            0x0E,  # Sub-function code
            0x01,  # Device ID code
            0x01,  # Conformity level (BASIC)
            0x00,  # More follows (False)
            0x00,  # Next object ID
            0x03,  # Number of objects
        )
        # Add object 0x00: "Vendor"
        response += struct.pack(">BB", 0x00, 6) + b"Vendor"
        # Add object 0x01: "Product"
        response += struct.pack(">BB", 0x01, 7) + b"Product"
        # Add object 0x02: "1.0"
        response += struct.pack(">BB", 0x02, 3) + b"1.0"

        result = pdu.decode_response(response)

        assert result.device_id_code == 0x01
        assert result.conformity_level == ConformityLevel.BASIC
        assert result.more is False
        assert result.next_object_id == 0x00
        assert result.number_of_objects == 0x03
        assert result.objects == {0x00: b"Vendor", 0x01: b"Product", 0x02: b"1.0"}

    def test_decode_response_more_follows(self) -> None:
        """Test decoding a response with more follows flag set."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)

        response = struct.pack(
            ">BBBBBBB",
            0x2B,  # Function code
            0x0E,  # Sub-function code
            0x01,  # Device ID code
            0x02,  # Conformity level (REGULAR)
            0xFF,  # More follows (True)
            0x03,  # Next object ID
            0x01,  # Number of objects
        )
        # Add one object
        response += struct.pack(">BB", 0x00, 4) + b"Test"

        result = pdu.decode_response(response)

        assert result.more is True
        assert result.next_object_id == 0x03

    def test_decode_response_invalid_function_code(self) -> None:
        """Test decoding response with invalid function code."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)

        response = struct.pack(
            ">BBBBBBB",
            0x03,  # Wrong function code
            0x0E,
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,
        )

        with pytest.raises(ValueError, match=r"Invalid function code: expected 0x2b, received 0x03"):
            pdu.decode_response(response)

    def test_decode_response_invalid_sub_function_code(self) -> None:
        """Test decoding response with invalid sub-function code."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)

        response = struct.pack(
            ">BBBBBBB",
            0x2B,
            0x0F,  # Wrong sub-function code
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,
        )

        with pytest.raises(ValueError, match=r"Invalid sub function code: expected 0x0e, received 0x0f"):
            pdu.decode_response(response)

    def test_decode_response_invalid_more_value(self) -> None:
        """Test decoding response with invalid 'more' value."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)

        response = struct.pack(
            ">BBBBBBB",
            0x2B,
            0x0E,
            0x01,
            0x01,
            0x01,  # Invalid 'more' value (must be 0x00 or 0xFF)
            0x00,
            0x00,
        )

        with pytest.raises(ValueError, match=r"Invalid 'more' value: 0x01"):
            pdu.decode_response(response)

    def test_decode_response_empty_objects(self) -> None:
        """Test decoding response with no objects."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)

        response = struct.pack(
            ">BBBBBBB",
            0x2B,
            0x0E,
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,  # Number of objects = 0
        )

        result = pdu.decode_response(response)

        assert result.number_of_objects == 0
        assert result.objects == {}

    def test_decode_response_multiple_objects(self) -> None:
        """Test decoding response with multiple objects."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x02, object_id=0x00)

        response = struct.pack(
            ">BBBBBBB",
            0x2B,
            0x0E,
            0x02,
            0x03,  # EXTENDED conformity level
            0x00,
            0x00,
            0x05,  # 5 objects
        )
        # Add objects
        response += struct.pack(">BB", 0x00, 10) + b"VendorName"
        response += struct.pack(">BB", 0x01, 11) + b"ProductCode"
        response += struct.pack(">BB", 0x02, 5) + b"v1.23"
        response += struct.pack(">BB", 0x03, 17) + b"http://vendor.com"
        response += struct.pack(">BB", 0x04, 12) + b"ProductName!"

        result = pdu.decode_response(response)

        assert result.conformity_level == ConformityLevel.EXTENDED
        assert result.number_of_objects == 5
        assert len(result.objects) == 5
        assert result.objects[0x00] == b"VendorName"
        assert result.objects[0x01] == b"ProductCode"
        assert result.objects[0x02] == b"v1.23"
        assert result.objects[0x03] == b"http://vendor.com"
        assert result.objects[0x04] == b"ProductName!"

    def test_decode_response_extra_bytes_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test decoding response triggers warning when object length extends past response end."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)

        response = struct.pack(
            ">BBBBBBB",
            0x2B,
            0x0E,
            0x01,
            0x01,
            0x00,
            0x00,
            0x01,
        )
        # Add an object with length 10 but only provide 5 bytes of data
        # This makes offset jump to 7 + 2 + 10 = 19, but response is only 7 + 2 + 5 = 14 bytes
        response += struct.pack(">BB", 0x00, 10) + b"Short"

        with caplog.at_level(logging.WARNING):
            result = pdu.decode_response(response)

        # The warning is logged when offset != len(response)
        # In this case, offset = 19 > len(response) = 14, so warning logged
        assert "Response has" in caplog.text
        assert "extra bytes" in caplog.text
        # The object will contain only the 5 bytes that were actually present
        assert result.objects == {0x00: b"Short"}

    def test_decode_response_all_conformity_levels(self) -> None:
        """Test decoding response with different conformity levels."""
        conformity_levels = [
            (0x01, ConformityLevel.BASIC),
            (0x02, ConformityLevel.REGULAR),
            (0x03, ConformityLevel.EXTENDED),
            (0x81, ConformityLevel.BASIC_PLUS),
            (0x82, ConformityLevel.REGULAR_PLUS),
            (0x83, ConformityLevel.EXTENDED_PLUS),
        ]

        for level_byte, expected_level in conformity_levels:
            pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)

            response = struct.pack(
                ">BBBBBBB",
                0x2B,
                0x0E,
                0x01,
                level_byte,
                0x00,
                0x00,
                0x00,
            )

            result = pdu.decode_response(response)
            assert result.conformity_level == expected_level

    def test_decode_response_object_with_empty_value(self) -> None:
        """Test decoding response with object that has empty value."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)

        response = struct.pack(
            ">BBBBBBB",
            0x2B,
            0x0E,
            0x01,
            0x01,
            0x00,
            0x00,
            0x01,
        )
        # Add object with 0 length
        response += struct.pack(">BB", 0x00, 0)

        result = pdu.decode_response(response)

        assert result.objects == {0x00: b""}

    def test_function_code_and_sub_function_code(self) -> None:
        """Test that function code and sub-function code are correct."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)
        assert pdu.function_code == 0x2B
        assert pdu.sub_function_code == 0x0E


class TestReadDeviceIdentificationPDUGetExpectedResponseDataLength:
    """Test get_expected_response_data_length method."""

    def test_insufficient_data_for_header(self) -> None:
        """Test with insufficient data to read header."""
        # Header is 7 bytes, provide only 6
        data = b"\x0e\x01\x01\x00\x00\x03"
        result = ReadDeviceIdentificationPDU.get_expected_response_data_length(data)
        assert result is None

    def test_invalid_sub_function_code(self) -> None:
        """Test with invalid sub-function code."""
        # Sub-function code should be 0x0E, but provide 0x0F
        data = struct.pack(">BBBBBB", 0x0F, 0x01, 0x01, 0x00, 0x00, 0x00)
        with pytest.raises(Exception, match=r"Expected sub-function code"):
            ReadDeviceIdentificationPDU.get_expected_response_data_length(data)

    def test_zero_objects(self) -> None:
        """Test with zero objects."""
        data = struct.pack(">BBBBBB", 0x0E, 0x01, 0x01, 0x00, 0x00, 0x00)
        result = ReadDeviceIdentificationPDU.get_expected_response_data_length(data)
        assert result == 6

    def test_single_object_complete(self) -> None:
        """Test with single complete object."""
        data = struct.pack(">BBBBBB", 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01)
        # Add object: ID=0x00, Length=6, Value="Vendor"
        data += struct.pack(">BB", 0x00, 6) + b"Vendor"
        result = ReadDeviceIdentificationPDU.get_expected_response_data_length(data)
        assert result == 6 + 2 + 6  # header + obj_header + obj_value

    def test_single_object_incomplete_header(self) -> None:
        """Test with single object but incomplete object header."""
        data = struct.pack(">BBBBBB", 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01)
        # Add only 1 byte of object header (need 2)
        data += b"\x00"
        result = ReadDeviceIdentificationPDU.get_expected_response_data_length(data)
        assert result is None

    def test_single_object_incomplete_value(self) -> None:
        """Test with single object but incomplete value."""
        data = struct.pack(">BBBBBB", 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01)
        # Add object header claiming length 10, but only provide 5 bytes
        data += struct.pack(">BB", 0x00, 10) + b"Short"
        result = ReadDeviceIdentificationPDU.get_expected_response_data_length(data)
        assert result == 18

    def test_multiple_objects_complete(self) -> None:
        """Test with multiple complete objects."""
        data = struct.pack(">BBBBBB", 0x0E, 0x01, 0x01, 0x00, 0x00, 0x03)
        # Add three objects
        data += struct.pack(">BB", 0x00, 6) + b"Vendor"
        data += struct.pack(">BB", 0x01, 7) + b"Product"
        data += struct.pack(">BB", 0x02, 3) + b"1.0"
        result = ReadDeviceIdentificationPDU.get_expected_response_data_length(data)
        # header(6) + obj1(2+6) + obj2(2+7) + obj3(2+3)  # noqa: ERA001
        assert result == 6 + 8 + 9 + 5

    def test_multiple_objects_incomplete_second_object(self) -> None:
        """Test with multiple objects where second object is incomplete."""
        data = struct.pack(">BBBBBB", 0x0E, 0x01, 0x01, 0x00, 0x00, 0x03)
        # Add first object complete
        data += struct.pack(">BB", 0x00, 6) + b"Vendor"
        # Add second object header only
        data += struct.pack(">BB", 0x01, 10)
        result = ReadDeviceIdentificationPDU.get_expected_response_data_length(data)
        assert result is None

    def test_object_with_empty_value(self) -> None:
        """Test with object having zero-length value."""
        data = struct.pack(">BBBBBB", 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01)
        # Add object with length 0
        data += struct.pack(">BB", 0x00, 0)
        result = ReadDeviceIdentificationPDU.get_expected_response_data_length(data)
        assert result == 6 + 2  # header + obj_header

    def test_multiple_objects_with_varying_lengths(self) -> None:
        """Test with multiple objects of varying lengths."""
        data = struct.pack(">BBBBBB", 0x0E, 0x02, 0x03, 0x00, 0x00, 0x05)
        # Add objects of different sizes
        data += struct.pack(">BB", 0x00, 10) + b"VendorName"
        data += struct.pack(">BB", 0x01, 0)  # Empty
        data += struct.pack(">BB", 0x02, 5) + b"v1.23"
        data += struct.pack(">BB", 0x03, 17) + b"http://vendor.com"
        data += struct.pack(">BB", 0x04, 1) + b"X"
        result = ReadDeviceIdentificationPDU.get_expected_response_data_length(data)
        # header(6) + obj1(2+10) + obj2(2+0) + obj3(2+5) + obj4(2+17) + obj5(2+1)  # noqa: ERA001
        assert result == 6 + 12 + 2 + 7 + 19 + 3

    def test_more_follows_flag_variations(self) -> None:
        """Test that 'more follows' flag doesn't affect length calculation."""
        # Test with more=0x00
        data1 = struct.pack(">BBBBBB", 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01)
        data1 += struct.pack(">BB", 0x00, 4) + b"Test"
        result1 = ReadDeviceIdentificationPDU.get_expected_response_data_length(data1)

        # Test with more=0xFF
        data2 = struct.pack(">BBBBBB", 0x0E, 0x01, 0x01, 0xFF, 0x00, 0x01)
        data2 += struct.pack(">BB", 0x00, 4) + b"Test"
        result2 = ReadDeviceIdentificationPDU.get_expected_response_data_length(data2)

        assert result1 == result2 == 6 + 2 + 4
