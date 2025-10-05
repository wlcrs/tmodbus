"""Test module for tmodbus/pdu/coils.py ."""

import struct

import pytest
from tmodbus.exceptions import InvalidRequestError, InvalidResponseError
from tmodbus.pdu import ReadCoilsPDU, WriteMultipleCoilsPDU, WriteSingleCoilPDU


class TestReadCoilsPDU:
    """Test class for ReadCoilsPDU decode_request and encode_response methods."""

    def test_read_coils_address_validation(self) -> None:
        """Test validation of address in Read Coils PDU."""
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535\."):
            ReadCoilsPDU(start_address=-1, quantity=1)
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535\."):
            ReadCoilsPDU(start_address=65536, quantity=1)

    def test_read_coils_quantity_validation(self) -> None:
        """Test validation of quantity in Read Coils PDU."""
        with pytest.raises(ValueError, match=r"Quantity must be between 1 and 2000."):
            ReadCoilsPDU(start_address=1, quantity=0)
        with pytest.raises(ValueError, match=r"Quantity must be between 1 and 2000."):
            ReadCoilsPDU(start_address=1, quantity=2001)

    def test_read_coils_encode_request(self) -> None:
        """Test encoding of Read Coils PDU."""
        pdu = ReadCoilsPDU(start_address=1, quantity=10)
        expected_bytes = struct.pack(">BHH", 0x01, 1, 10)

        assert pdu.encode_request() == expected_bytes

    def test_read_coils_decode_response(self) -> None:
        """Test decoding of Read Coils PDU."""
        pdu = ReadCoilsPDU(start_address=1, quantity=1)
        response_bytes = bytearray.fromhex("01 01 01")
        assert pdu.decode_response(response_bytes) == [True]

        pdu = ReadCoilsPDU(start_address=2, quantity=3)
        assert pdu.decode_response(bytearray.fromhex("01 01 04")) == [False, False, True]
        assert pdu.decode_response(bytearray.fromhex("01 01 05")) == [True, False, True]

    def test_read_coils_invalid_response(self) -> None:
        """Test invalid response handling in Read Coils PDU."""
        pdu = ReadCoilsPDU(start_address=1, quantity=5)

        with pytest.raises(InvalidResponseError, match="Expected response to start with function code and byte count"):
            pdu.decode_response(bytearray.fromhex("FF"))

        # Invalid function code
        with pytest.raises(InvalidResponseError, match="Invalid function code: expected 0x01, received 0x02"):
            pdu.decode_response(bytearray.fromhex("02 01 05"))

        # Invalid length
        with pytest.raises(InvalidResponseError, match="Invalid response PDU length: expected 10, got 5"):
            pdu.decode_response(bytearray.fromhex("01 08 02 03 04"))

        # Invalid byte count
        with pytest.raises(InvalidResponseError, match="Invalid byte count: expected 1, got 8"):
            pdu.decode_response(bytearray.fromhex("01 08 02 03 04 05 FF FF FF FF"))

    def test_decode_request_valid(self) -> None:
        """Test decoding a valid Read Coils request."""
        request = struct.pack(">BHH", 0x01, 100, 10)
        pdu = ReadCoilsPDU.decode_request(request)
        assert pdu.start_address == 100
        assert pdu.quantity == 10

    def test_decode_request_struct_error(self) -> None:
        """Test decode_request with invalid struct format."""
        with pytest.raises(
            InvalidRequestError,
            match=r"Expected request to start with function code, address, and quantity",
        ):
            ReadCoilsPDU.decode_request(b"\x01\x00")

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decode_request with invalid function code."""
        request = struct.pack(">BHH", 0x02, 100, 10)
        with pytest.raises(InvalidRequestError, match=r"Invalid function code: expected 0x01, received 0x02"):
            ReadCoilsPDU.decode_request(request)

    def test_encode_response_single_byte(self) -> None:
        """Test encoding response with single byte of coils."""
        pdu = ReadCoilsPDU(start_address=0, quantity=5)
        values = [True, False, True, False, True]
        response = pdu.encode_response(values)
        # Expected: function code (0x01) + byte count (0x01) + data (0x15 = 0b00010101)
        assert response == b"\x01\x01\x15"

    def test_encode_response_multiple_bytes(self) -> None:
        """Test encoding response with multiple bytes of coils."""
        pdu = ReadCoilsPDU(start_address=0, quantity=16)
        values = [True] * 8 + [False] * 8
        response = pdu.encode_response(values)
        # Expected: function code + byte count (2) + data (0xFF 0x00)
        assert response == b"\x01\x02\xff\x00"

    def test_encode_response_partial_byte(self) -> None:
        """Test encoding response with partial last byte."""
        pdu = ReadCoilsPDU(start_address=0, quantity=10)
        values = [True] * 10
        response = pdu.encode_response(values)
        # Expected: function code + byte count (2) + data (0xFF 0x03 = 0b11111111 0b00000011)
        assert response == b"\x01\x02\xff\x03"


class TestWriteSingleCoilPDU:
    """Test class for WriteSingleCoilPDU decode_request and encode_response methods."""

    def test_write_single_coil_pdu(self) -> None:
        """Test Write Single Coil PDU."""
        pdu = WriteSingleCoilPDU(address=1, value=True)
        assert pdu.encode_request() == bytearray.fromhex("05 00 01 FF 00")

        pdu = WriteSingleCoilPDU(address=12345, value=False)
        assert pdu.encode_request() == bytearray.fromhex("05 30 39 00 00")

    def test_write_single_coil_decode_response(self) -> None:
        """Test decoding of Write Single Coil PDU."""
        pdu = WriteSingleCoilPDU(address=1, value=True)
        response_bytes = bytearray.fromhex("05 00 01 FF 00")
        assert pdu.decode_response(response_bytes) is True

        with pytest.raises(InvalidResponseError, match="Expected response to match request"):
            pdu.decode_response(bytearray.fromhex("06 00 01 FF 00"))

        pdu = WriteSingleCoilPDU(address=12345, value=False)
        response_bytes = bytearray.fromhex("05 30 39 00 00")
        assert pdu.decode_response(response_bytes) is False

        with pytest.raises(InvalidResponseError, match="Expected response to match request"):
            pdu.decode_response(bytearray.fromhex("06 30 39 00 00"))

        with pytest.raises(InvalidResponseError, match="Expected response to match request"):
            pdu.decode_response(bytearray.fromhex("05 30 40 00 00"))

    def test_decode_request_valid_on(self) -> None:
        """Test decoding a valid Write Single Coil request (ON)."""
        request = struct.pack(">BHH", 0x05, 100, 0xFF00)
        pdu = WriteSingleCoilPDU.decode_request(request)
        assert pdu.address == 100
        assert pdu.value is True

    def test_decode_request_valid_off(self) -> None:
        """Test decoding a valid Write Single Coil request (OFF)."""
        request = struct.pack(">BHH", 0x05, 200, 0x0000)
        pdu = WriteSingleCoilPDU.decode_request(request)
        assert pdu.address == 200
        assert pdu.value is False

    def test_decode_request_struct_error(self) -> None:
        """Test decode_request with invalid struct format."""
        with pytest.raises(
            InvalidRequestError,
            match=r"Expected request to start with function code, address, and value",
        ):
            WriteSingleCoilPDU.decode_request(b"\x05\x00")

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decode_request with invalid function code."""
        request = struct.pack(">BHH", 0x06, 100, 0xFF00)
        with pytest.raises(InvalidRequestError, match=r"Invalid function code: expected 0x05, received 0x06"):
            WriteSingleCoilPDU.decode_request(request)

    def test_decode_request_invalid_coil_value(self) -> None:
        """Test decode_request with invalid coil value."""
        request = struct.pack(">BHH", 0x05, 100, 0x1234)
        with pytest.raises(InvalidRequestError, match=r"Invalid coil value: 0x1234"):
            WriteSingleCoilPDU.decode_request(request)

    def test_encode_response_on(self) -> None:
        """Test encoding response for writing coil ON."""
        pdu = WriteSingleCoilPDU(address=100, value=True)
        response = pdu.encode_response(True)  # noqa: FBT003
        assert response == struct.pack(">BHH", 0x05, 100, 0xFF00)

    def test_encode_response_off(self) -> None:
        """Test encoding response for writing coil OFF."""
        pdu = WriteSingleCoilPDU(address=200, value=False)
        response = pdu.encode_response(False)  # noqa: FBT003
        assert response == struct.pack(">BHH", 0x05, 200, 0x0000)


class TestWriteMultipleCoilsPDU:
    """Test class for WriteMultipleCoilsPDU decode_request and encode_response methods."""

    def test_write_multiple_coils_validation(self) -> None:
        """Test validation of Write Multiple Coils PDU."""
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535\."):
            WriteMultipleCoilsPDU(start_address=-1, values=[True])
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535\."):
            WriteMultipleCoilsPDU(start_address=65536, values=[True])
        with pytest.raises(ValueError, match=r"Number of coils must be between 1 and 1968\."):
            WriteMultipleCoilsPDU(start_address=1, values=[True] * 1969)

    @pytest.mark.parametrize(
        ("start_address", "values", "expected_bytes"),
        [
            (10, [True, False, True], bytearray.fromhex("0F 00 0A 00 03 01 05")),
            (12345, [False] * 16, bytearray.fromhex("0F 30 39 00 10 02 00 00")),
            (12345, [True] * 19, bytearray.fromhex("0F 30 39 00 13 03 FF FF 07")),
            (1, [True] * 5, bytearray.fromhex("0F 00 01 00 05 01 1F")),
            (1, [True], bytearray.fromhex("0F 00 01 00 01 01 01")),
        ],
    )
    def test_write_multiple_coils_encode_request(
        self,
        start_address: int,
        values: list[bool],
        expected_bytes: bytearray,
    ) -> None:
        """Test encoding of Write Multiple Coils PDU."""
        pdu = WriteMultipleCoilsPDU(start_address=start_address, values=values)
        assert pdu.encode_request() == expected_bytes

    @pytest.mark.parametrize(
        ("response", "address", "value_count"),
        [
            (bytearray.fromhex("0F 00 0A 00 07"), 10, 7),
            (bytearray.fromhex("0F 30 39 00 10"), 12345, 16),
            (bytearray.fromhex("0F 30 39 00 13"), 12345, 19),
            (bytearray.fromhex("0F 00 01 00 05"), 1, 5),
            (bytearray.fromhex("0F 00 01 00 01"), 1, 1),
        ],
    )
    def test_write_multiple_coils_decode_response(self, response: bytearray, address: int, value_count: int) -> None:
        """Test decoding of Write Multiple Coils PDU."""
        pdu = WriteMultipleCoilsPDU(start_address=address, values=[True] * value_count)
        assert pdu.decode_response(response) == value_count

        invalid_pdu = WriteMultipleCoilsPDU(start_address=address, values=[False] * (value_count + 1))
        with pytest.raises(InvalidResponseError, match="Device response does not match request"):
            invalid_pdu.decode_response(response)

    def test_decode_request_valid_single_byte(self) -> None:
        """Test decoding a valid Write Multiple Coils request with single byte."""
        # Function code + address + quantity + byte count + data
        request = struct.pack(">BHHB", 0x0F, 100, 5, 1) + b"\x15"
        pdu = WriteMultipleCoilsPDU.decode_request(request)
        assert pdu.address == 100
        assert pdu.values == [True, False, True, False, True]

    def test_decode_request_valid_multiple_bytes(self) -> None:
        """Test decoding a valid Write Multiple Coils request with multiple bytes."""
        request = struct.pack(">BHHB", 0x0F, 50, 16, 2) + b"\xff\x00"
        pdu = WriteMultipleCoilsPDU.decode_request(request)
        assert pdu.address == 50
        assert len(pdu.values) == 16
        assert pdu.values == [True] * 8 + [False] * 8

    def test_decode_request_too_short(self) -> None:
        """Test decode_request with request too short."""
        with pytest.raises(InvalidRequestError, match=r"Request too short for Write Multiple Coils"):
            WriteMultipleCoilsPDU.decode_request(b"\x0f\x00\x01")

    def test_decode_request_too_short_for_struct(self) -> None:
        """Test decode_request raises error on too-short request."""
        with pytest.raises(InvalidRequestError, match=r"Request too short for Write Multiple Coils"):
            WriteMultipleCoilsPDU.decode_request(b"\x0f\x00\x01")  # Only 3 bytes

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decode_request with invalid function code."""
        request = struct.pack(">BHHB", 0x10, 100, 5, 1) + b"\x15"
        with pytest.raises(InvalidRequestError, match=r"Invalid function code: expected 0x0f, received 0x10"):
            WriteMultipleCoilsPDU.decode_request(request)

    def test_decode_request_invalid_quantity_too_low(self) -> None:
        """Test decode_request with quantity too low."""
        request = struct.pack(">BHHB", 0x0F, 100, 0, 1) + b"\x00"
        with pytest.raises(InvalidRequestError, match=r"Number of coils must be between 1 and 1968\."):
            WriteMultipleCoilsPDU.decode_request(request)

    def test_decode_request_invalid_quantity_too_high(self) -> None:
        """Test decode_request with quantity too high."""
        request = struct.pack(">BHHB", 0x0F, 100, 1969, 247) + b"\x00" * 247
        with pytest.raises(InvalidRequestError, match=r"Number of coils must be between 1 and 1968\."):
            WriteMultipleCoilsPDU.decode_request(request)

    def test_decode_request_invalid_length(self) -> None:
        """Test decode_request with invalid request length."""
        request = struct.pack(">BHHB", 0x0F, 100, 5, 1) + b"\x15\xff"  # Extra byte
        with pytest.raises(InvalidRequestError, match=r"Invalid request length: expected 7, got 8"):
            WriteMultipleCoilsPDU.decode_request(request)

    def test_decode_request_invalid_byte_count(self) -> None:
        """Test decode_request with invalid byte count."""
        request = struct.pack(">BHHB", 0x0F, 100, 5, 2) + b"\x15\x00"  # Wrong byte count
        with pytest.raises(InvalidRequestError, match=r"Invalid byte count: expected 1, got 2"):
            WriteMultipleCoilsPDU.decode_request(request)

    def test_encode_response(self) -> None:
        """Test encoding response for writing multiple coils."""
        pdu = WriteMultipleCoilsPDU(start_address=100, values=[True] * 10)
        response = pdu.encode_response(10)
        assert response == struct.pack(">BHH", 0x0F, 100, 10)
