import pytest

from tmodbus.exceptions import InvalidRequestError, InvalidResponseError
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteMultipleRegistersPDU, WriteSingleRegisterPDU
from tmodbus.pdu.holding_registers import (
    RawReadHoldingRegistersPDU,
    RawReadInputRegistersPDU,
    RawWriteMultipleRegistersPDU,
    ReadInputRegistersPDU,
)


class TestReadHoldingRegistersPDU:
    """Tests for ReadHoldingRegistersPDU (moved from standalone functions)."""

    def test_read_holding_registers_quantity_validation(self):
        """Test validation of quantity in Read Holding Registers PDU."""

    with pytest.raises(ValueError, match=r"Quantity must be between 1 and 125."):
        ReadHoldingRegistersPDU(start_address=1, quantity=0)
    with pytest.raises(ValueError, match=r"Quantity must be between 1 and 125."):
        ReadHoldingRegistersPDU(start_address=1, quantity=126)

    def test_read_holding_registers_encode_request(self):
        """Test encoding of Read Holding Registers PDU."""
        pdu = ReadHoldingRegistersPDU(start_address=1, quantity=10)
        assert pdu.encode_request() == bytearray.fromhex("03 00 01 00 0A")

    def test_read_holding_registers_decode_response(self):
        """Test decoding of Read Holding Registers PDU."""
        pdu = ReadHoldingRegistersPDU(start_address=1, quantity=2)
        response_bytes = bytearray.fromhex("03 04 00 01 00 02")
        assert pdu.decode_response(response_bytes) == [1, 2]

        # Test with more registers
        pdu = ReadHoldingRegistersPDU(start_address=2, quantity=3)
        response_bytes = bytearray.fromhex("03 06 00 03 00 04 00 05")
        assert pdu.decode_response(response_bytes) == [3, 4, 5]

    def test_read_holding_registers_invalid_response(self):
        """Test invalid response handling in Read Holding Registers PDU."""
        pdu = ReadHoldingRegistersPDU(start_address=1, quantity=5)

        with pytest.raises(InvalidResponseError, match=r"Expected response to start with function code and byte count"):
            pdu.decode_response(bytearray.fromhex("FF"))

        # Invalid function code
        with pytest.raises(InvalidResponseError, match=r"Invalid function code: expected 03, received 04"):
            pdu.decode_response(bytearray.fromhex("04 01 05"))

        # Invalid length
        with pytest.raises(InvalidResponseError, match=r"Invalid response PDU length: expected 10, got 5"):
            pdu.decode_response(bytearray.fromhex("03 08 02 03 04"))

        # Invalid register count
        with pytest.raises(InvalidResponseError, match=r"Invalid register count: expected 5, got 4"):
            pdu.decode_response(bytearray.fromhex("03 08 02 03 04 05 FF FF FF FF"))

    def test_decode_request_too_short(self):
        """Test ReadHoldingRegistersPDU.decode_request raises on too-short request."""
        request = b"\x03\x12"
        with pytest.raises(
            InvalidRequestError, match=r"Expected request to start with function code, address, and quantity"
        ):
            ReadHoldingRegistersPDU.decode_request(request)

    def test_decode_request_invalid_function_code(self):
        """Test ReadHoldingRegistersPDU.decode_request raises on invalid function code."""
        request = b"\x04\x12\x34\x00\x0a"
        with pytest.raises(InvalidRequestError, match=r"Invalid function code"):
            ReadHoldingRegistersPDU.decode_request(request)


# ============================================================================
# RawReadHoldingRegistersPDU Tests
# ============================================================================


class TestRawReadHoldingRegistersPDU:
    """Tests for RawReadHoldingRegistersPDU."""

    def test_initialization_valid(self):
        """Test valid initialization."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=10)
        assert pdu.start_address == 100
        assert pdu.quantity == 10

    @pytest.mark.parametrize(
        ("start_address", "quantity", "expected_error"),
        [
            (-1, 10, "Address must be between 0 and 65535"),
            (65536, 10, "Address must be between 0 and 65535"),
            (100, 0, "Quantity must be between 1 and 125"),
            (100, 126, "Quantity must be between 1 and 125"),
        ],
    )
    def test_initialization_invalid(self, start_address, quantity, expected_error):
        """Test invalid initialization."""
        with pytest.raises(ValueError, match=expected_error):
            RawReadHoldingRegistersPDU(start_address=start_address, quantity=quantity)

    def test_encode_request(self):
        """Test encoding request."""
        pdu = RawReadHoldingRegistersPDU(start_address=0x1234, quantity=10)
        encoded = pdu.encode_request()
        assert encoded == b"\x03\x12\x34\x00\x0a"

    def test_decode_response_valid(self):
        """Test decoding valid response."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x03\x06\x12\x34\x56\x78\x9a\xbc"
        result = pdu.decode_response(response)
        assert result == b"\x12\x34\x56\x78\x9a\xbc"

    def test_decode_response_invalid_function_code(self):
        """Test decoding response with invalid function code."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x04\x06\x12\x34\x56\x78\x9a\xbc"
        with pytest.raises(InvalidResponseError, match="Invalid function code"):
            pdu.decode_response(response)

    def test_decode_response_invalid_length(self):
        """Test decoding response with invalid length."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x03\x06\x12\x34"
        with pytest.raises(InvalidResponseError, match="Invalid response PDU length"):
            pdu.decode_response(response)

    def test_decode_response_invalid_register_count(self):
        """Test decoding response with mismatched register count."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x03\x04\x12\x34\x56\x78"
        with pytest.raises(InvalidResponseError, match="Invalid register count"):
            pdu.decode_response(response)

    def test_decode_response_too_short(self):
        """Test decoding response that is too short."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x03"
        with pytest.raises(InvalidResponseError, match="Expected response to start with function code and byte count"):
            pdu.decode_response(response)

    def test_decode_request_valid(self):
        """Test decoding valid request."""
        request = b"\x03\x12\x34\x00\x0a"
        pdu = RawReadHoldingRegistersPDU.decode_request(request)
        assert pdu.start_address == 0x1234
        assert pdu.quantity == 10

    def test_decode_request_invalid_function_code(self):
        """Test decoding request with invalid function code."""
        request = b"\x04\x12\x34\x00\x0a"
        with pytest.raises(InvalidRequestError, match="Invalid function code"):
            RawReadHoldingRegistersPDU.decode_request(request)

    def test_decode_request_too_short(self):
        """Test decoding request that is too short."""
        request = b"\x03\x12"
        with pytest.raises(
            InvalidRequestError, match="Expected request to start with function code, address, and quantity"
        ):
            RawReadHoldingRegistersPDU.decode_request(request)

    def test_encode_response(self):
        """Test encoding response."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        value = b"\x12\x34\x56\x78\x9a\xbc"
        encoded = pdu.encode_response(value)
        assert encoded == b"\x03\x06\x12\x34\x56\x78\x9a\xbc"


# ============================================================================
# RawReadInputRegistersPDU Tests
# ============================================================================


class TestRawReadInputRegistersPDU:
    """Tests for RawReadInputRegistersPDU."""

    def test_function_code(self):
        """Test that the function code is correct."""
        pdu = RawReadInputRegistersPDU(start_address=100, quantity=10)
        assert pdu.function_code == 0x04

    def test_encode_request(self):
        """Test encoding request uses correct function code."""
        pdu = RawReadInputRegistersPDU(start_address=0x1234, quantity=10)
        encoded = pdu.encode_request()
        assert encoded == b"\x04\x12\x34\x00\x0a"

    def test_decode_request(self):
        """Test decoding request."""
        request = b"\x04\x12\x34\x00\x0a"
        pdu = RawReadInputRegistersPDU.decode_request(request)
        assert pdu.start_address == 0x1234
        assert pdu.quantity == 10


# ============================================================================
# ReadInputRegistersPDU Tests
# ============================================================================


class TestReadInputRegistersPDU:
    """Tests for ReadInputRegistersPDU."""

    def test_function_code(self):
        """Test that the function code is correct."""
        pdu = ReadInputRegistersPDU(start_address=100, quantity=10)
        assert pdu.function_code == 0x04

    def test_encode_request(self):
        """Test encoding request uses correct function code."""
        pdu = ReadInputRegistersPDU(start_address=0x1234, quantity=10)
        encoded = pdu.encode_request()
        assert encoded == b"\x04\x12\x34\x00\x0a"

    def test_decode_response(self):
        """Test decoding response."""
        pdu = ReadInputRegistersPDU(start_address=100, quantity=3)
        response = b"\x04\x06\x12\x34\x56\x78\x9a\xbc"
        result = pdu.decode_response(response)
        assert result == [0x1234, 0x5678, 0x9ABC]

    def test_decode_request(self):
        """Test decoding request."""
        request = b"\x04\x12\x34\x00\x0a"
        pdu = ReadInputRegistersPDU.decode_request(request)
        assert pdu.raw_pdu.start_address == 0x1234
        assert pdu.raw_pdu.quantity == 10

    def test_encode_response(self):
        """Test encoding response."""
        pdu = ReadInputRegistersPDU(start_address=100, quantity=3)
        values = [0x1234, 0x5678, 0x9ABC]
        encoded = pdu.encode_response(values)
        assert encoded == b"\x04\x06\x12\x34\x56\x78\x9a\xbc"


# ============================================================================
# WriteSingleRegisterPDU Additional Tests
# ============================================================================


class TestWriteSingleRegisterPDU:
    """Additional tests for WriteSingleRegisterPDU."""

    @pytest.mark.parametrize(
        ("address", "value", "expected_bytes"),
        [
            (0, 0, b"\x06\x00\x00\x00\x00"),
            (65535, 65535, b"\x06\xff\xff\xff\xff"),
            (0x1234, 0x5678, b"\x06\x12\x34\x56\x78"),
        ],
    )
    def test_encode_request_edge_cases(self, address, value, expected_bytes):
        """Test encoding with edge case values."""
        pdu = WriteSingleRegisterPDU(address=address, value=value)
        assert pdu.encode_request() == expected_bytes

    def test_decode_request_valid(self):
        """Test decoding valid request."""
        request = b"\x06\x12\x34\x56\x78"
        pdu = WriteSingleRegisterPDU.decode_request(request)
        assert pdu.address == 0x1234
        assert pdu.value == 0x5678

    def test_decode_request_invalid_function_code(self):
        """Test decoding request with invalid function code."""
        request = b"\x03\x12\x34\x56\x78"
        with pytest.raises(InvalidRequestError, match="Invalid function code"):
            WriteSingleRegisterPDU.decode_request(request)

    def test_decode_request_too_short(self):
        """Test decoding request that is too short."""
        request = b"\x06\x12"
        with pytest.raises(
            InvalidRequestError, match="Expected request to start with function code, address, and value"
        ):
            WriteSingleRegisterPDU.decode_request(request)

    def test_encode_response(self):
        """Test encoding response."""
        pdu = WriteSingleRegisterPDU(address=0x1234, value=0x5678)
        encoded = pdu.encode_response(0x5678)
        assert encoded == b"\x06\x12\x34\x56\x78"

    def test_rtu_response_data_length(self):
        """Test RTU response data length constant."""
        assert WriteSingleRegisterPDU.rtu_response_data_length == 4

    def test_write_single_register_validation(self):
        """Test validation of Write Single Register PDU."""
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535."):
            WriteSingleRegisterPDU(address=-1, value=123)
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535."):
            WriteSingleRegisterPDU(address=65536, value=123)
        with pytest.raises(ValueError, match=r"Value must be between 0 and 65535."):
            WriteSingleRegisterPDU(address=1, value=-1)
        with pytest.raises(ValueError, match=r"Value must be between 0 and 65535."):
            WriteSingleRegisterPDU(address=1, value=65536)

    def test_write_single_register_encode_request(self):
        """Test encoding of Write Single Register PDU."""
        pdu = WriteSingleRegisterPDU(address=1, value=12345)
        assert pdu.encode_request() == bytearray.fromhex("06 00 01 30 39")

    def test_write_single_register_decode_response(self):
        """Test decoding of Write Single Register PDU."""
        pdu = WriteSingleRegisterPDU(address=1, value=12345)
        response_bytes = bytearray.fromhex("06 00 01 30 39")
        assert pdu.decode_response(response_bytes) == 12345

        with pytest.raises(InvalidResponseError, match="Expected response to match request"):
            pdu.decode_response(bytearray.fromhex("07 00 01 30 39"))


# ============================================================================
# RawWriteMultipleRegistersPDU Tests
# ============================================================================


class TestRawWriteMultipleRegistersPDU:
    """Tests for RawWriteMultipleRegistersPDU."""

    def test_initialization_valid(self):
        """Test valid initialization."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=100, content=content)
        assert pdu.start_address == 100
        assert pdu.content == content

    def test_initialization_pads_odd_length(self):
        """Test that odd-length content is padded."""
        content = b"\x12\x34\x56"
        pdu = RawWriteMultipleRegistersPDU(start_address=100, content=content)
        assert pdu.content == b"\x12\x34\x56\x00"

    @pytest.mark.parametrize(
        ("start_address", "content", "expected_error"),
        [
            (-1, b"\x12\x34", "Address must be between 0 and 65535"),
            (65536, b"\x12\x34", "Address must be between 0 and 65535"),
            (100, b"", "Content must not be empty"),
            (100, b"\x00" * 247, "Content exceeds maximum length"),
        ],
    )
    def test_initialization_invalid(self, start_address, content, expected_error):
        """Test invalid initialization."""
        with pytest.raises(ValueError, match=expected_error):
            RawWriteMultipleRegistersPDU(start_address=start_address, content=content)

    def test_encode_request(self):
        """Test encoding request."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=0x1000, content=content)
        encoded = pdu.encode_request()
        # Function code (0x10) + address (0x1000) + quantity (2) + byte count (4) + content
        expected = b"\x10\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        assert encoded == expected

    def test_decode_response_valid(self):
        """Test decoding valid response."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=0x1000, content=content)
        response = b"\x10\x10\x00\x00\x02"
        result = pdu.decode_response(response)
        assert result == 2

    def test_decode_response_invalid(self):
        """Test decoding invalid response."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=0x1000, content=content)
        response = b"\x10\x10\x00\x00\x03"  # Wrong quantity
        with pytest.raises(InvalidResponseError, match="Device response does not match request"):
            pdu.decode_response(response)

    def test_decode_request_valid(self):
        """Test decoding valid request."""
        request = b"\x10\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU.decode_request(request)
        assert pdu.start_address == 0x1000
        assert pdu.content == b"\x12\x34\x56\x78"

    def test_decode_request_too_short(self):
        """Test decoding request that is too short."""
        request = b"\x10\x10\x00"
        with pytest.raises(InvalidRequestError, match="Request too short"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_invalid_function_code(self):
        """Test decoding request with invalid function code."""
        request = b"\x03\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        with pytest.raises(InvalidRequestError, match="Invalid function code"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_odd_byte_count(self):
        """Test decoding request with odd byte count."""
        request = b"\x10\x10\x00\x00\x02\x05\x12\x34\x56\x78\x9a"
        with pytest.raises(InvalidRequestError, match="Byte count must be even"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_mismatched_quantity(self):
        """Test decoding request with mismatched quantity."""
        request = b"\x10\x10\x00\x00\x03\x04\x12\x34\x56\x78"
        with pytest.raises(InvalidRequestError, match="Invalid register count"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_invalid_data_length(self):
        """Test decoding request with invalid data length."""
        request = b"\x10\x10\x00\x00\x02\x04\x12\x34"
        with pytest.raises(InvalidRequestError, match="Invalid data length"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_encode_response(self):
        """Test encoding response."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=0x1000, content=content)
        encoded = pdu.encode_response(2)
        assert encoded == b"\x10\x10\x00\x00\x02"

    def test_rtu_response_data_length(self):
        """Test RTU response data length constant."""
        assert RawWriteMultipleRegistersPDU.rtu_response_data_length == 5


# ============================================================================
# WriteMultipleRegistersPDU Additional Tests
# ============================================================================


class TestWriteMultipleRegistersPDU:
    """Additional tests for WriteMultipleRegistersPDU."""

    def test_initialization_valid(self):
        """Test valid initialization."""
        values = [0x1234, 0x5678, 0x9ABC]
        pdu = WriteMultipleRegistersPDU(start_address=100, values=values)
        assert pdu.start_adress == 100  # Note: typo in source code
        assert pdu.values == values

    @pytest.mark.parametrize(
        ("start_address", "values", "expected_error"),
        [
            (-1, [100], "Address must be between 0 and 65535"),
            (65536, [100], "Address must be between 0 and 65535"),
            (100, [], "Number of registers must be between 1 and 123"),
            (100, [100] * 124, "Number of registers must be between 1 and 123"),
            (100, [-1], "Value must be between 0 and 65535"),
            (100, [65536], "Value must be between 0 and 65535"),
        ],
    )
    def test_initialization_invalid(self, start_address, values, expected_error):
        """Test invalid initialization."""
        with pytest.raises(ValueError, match=expected_error):
            WriteMultipleRegistersPDU(start_address=start_address, values=values)

    def test_write_multiple_registers_validation(self):
        """Test validation of Write Multiple Registers PDU."""
        with pytest.raises(ValueError, match="Address must be between 0 and 65535."):
            WriteMultipleRegistersPDU(start_address=-1, values=[123])
        with pytest.raises(ValueError, match="Address must be between 0 and 65535."):
            WriteMultipleRegistersPDU(start_address=65536, values=[123])
        with pytest.raises(ValueError, match="Number of registers must be between 1 and 123."):
            WriteMultipleRegistersPDU(start_address=1, values=[123] * 124)

        with pytest.raises(ValueError, match="Value must be between 0 and 65535: 70000"):
            WriteMultipleRegistersPDU(start_address=1, values=[70000])

    def test_write_multiple_registers_encode_request(self):
        """Test encoding of Write Multiple Registers PDU."""
        pdu = WriteMultipleRegistersPDU(start_address=1, values=[12345, 255])
        assert pdu.encode_request() == bytearray.fromhex("10 00 01 00 02 04 30 39 00 FF")

    def test_write_multiple_registers_decode_response(self):
        """Test decoding of Write Multiple Registers PDU."""
        pdu = WriteMultipleRegistersPDU(start_address=1, values=[12345, 255])
        response_bytes = bytearray.fromhex("10 00 01 00 02")
        assert pdu.decode_response(response_bytes) == 2

        with pytest.raises(InvalidResponseError, match="Device response does not match request"):
            pdu.decode_response(bytearray.fromhex("11 00 01 00 02"))

    def test_encode_request(self):
        """Test encoding request."""
        values = [0x1234, 0x5678]
        pdu = WriteMultipleRegistersPDU(start_address=0x1000, values=values)
        encoded = pdu.encode_request()
        expected = b"\x10\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        assert encoded == expected

    def test_decode_request_valid(self):
        """Test decoding valid request."""
        request = b"\x10\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        pdu = WriteMultipleRegistersPDU.decode_request(request)
        assert pdu.raw_pdu.start_address == 0x1000
        assert pdu.values == [0x1234, 0x5678]

    def test_encode_response(self):
        """Test encoding response."""
        values = [0x1234, 0x5678]
        pdu = WriteMultipleRegistersPDU(start_address=0x1000, values=values)
        # The raw_pdu.encode_response should be used
        encoded = pdu.raw_pdu.encode_response(2)
        assert encoded == b"\x10\x10\x00\x00\x02"

    def test_encode_response_delegates(self):
        """Test that WriteMultipleRegistersPDU.encode_response delegates to RawWriteMultipleRegistersPDU."""
        values = [0x1234, 0x5678]
        pdu = WriteMultipleRegistersPDU(start_address=0x1000, values=values)
        encoded = pdu.encode_response(2)
        assert encoded == b"\x10\x10\x00\x00\x02"

    def test_rtu_response_data_length(self):
        """Test RTU response data length constant."""
        assert WriteMultipleRegistersPDU.rtu_response_data_length == 4

    @pytest.mark.parametrize(
        "values",
        [
            [0, 0, 0],  # Minimum values
            [65535, 65535, 65535],  # Maximum values
            list(range(100)),  # Many values
            [0x0000, 0xFFFF, 0x1234, 0x5678, 0x9ABC, 0xDEF0],  # Mixed values
        ],
    )
    def test_round_trip(self, values):
        """Test encoding and decoding round trip."""
        pdu = WriteMultipleRegistersPDU(start_address=100, values=values)
        request = pdu.encode_request()
        decoded_pdu = WriteMultipleRegistersPDU.decode_request(request)
        assert decoded_pdu.values == values
