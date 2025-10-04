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

    def test_init_valid(self):
        """Test creating a valid ReadDeviceIdentificationPDU."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)
        assert pdu.read_device_id_code == 0x01
        assert pdu.object_id == 0x00

    def test_init_invalid_object_id_negative(self):
        """Test creating ReadDeviceIdentificationPDU with negative object_id."""
        with pytest.raises(ValueError, match=r"Object ID must be between 0x00 and 0xFF\."):
            ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=-1)

    def test_init_invalid_object_id_too_high(self):
        """Test creating ReadDeviceIdentificationPDU with object_id >= 0xFF."""
        with pytest.raises(ValueError, match=r"Object ID must be between 0x00 and 0xFF\."):
            ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0xFF)

    def test_encode_request(self):
        """Test encoding request."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)
        encoded = pdu.encode_request()
        # Function code (0x2B) + Sub-function (0x0E) + Read Device ID Code (0x01) + Object ID (0x00)
        assert encoded == b"\x2b\x0e\x01\x00"

    def test_encode_request_different_values(self):
        """Test encoding request with different values."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x04, object_id=0x05)
        encoded = pdu.encode_request()
        assert encoded == b"\x2b\x0e\x04\x05"

    def test_decode_response_basic(self):
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

    def test_decode_response_more_follows(self):
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

    def test_decode_response_invalid_function_code(self):
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

    def test_decode_response_invalid_sub_function_code(self):
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

    def test_decode_response_invalid_more_value(self):
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

    def test_decode_response_empty_objects(self):
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

    def test_decode_response_multiple_objects(self):
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

    def test_decode_response_extra_bytes_warning(self, caplog):
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

    def test_decode_response_all_conformity_levels(self):
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

    def test_decode_response_object_with_empty_value(self):
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

    def test_function_code_and_sub_function_code(self):
        """Test that function code and sub-function code are correct."""
        pdu = ReadDeviceIdentificationPDU(read_device_id_code=0x01, object_id=0x00)
        assert pdu.function_code == 0x2B
        assert pdu.sub_function_code == 0x0E
