"""Tests for tmodbus/pdu/holding_registers.py ."""

import pytest
from tmodbus.exceptions import InvalidRequestError, InvalidResponseError
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteMultipleRegistersPDU, WriteSingleRegisterPDU
from tmodbus.pdu.holding_registers import (
    MaskWriteRegisterPDU,
    RawReadHoldingRegistersPDU,
    RawReadInputRegistersPDU,
    RawWriteMultipleRegistersPDU,
    ReadInputRegistersPDU,
    ReadWriteMultipleRegistersPDU,
)


class TestReadHoldingRegistersPDU:
    """Tests for ReadHoldingRegistersPDU (moved from standalone functions)."""

    def test_read_holding_registers_quantity_validation(self) -> None:
        """Test validation of quantity in Read Holding Registers PDU."""

    with pytest.raises(ValueError, match=r"Quantity must be between 1 and 125."):
        ReadHoldingRegistersPDU(start_address=1, quantity=0)
    with pytest.raises(ValueError, match=r"Quantity must be between 1 and 125."):
        ReadHoldingRegistersPDU(start_address=1, quantity=126)

    def test_read_holding_registers_encode_request(self) -> None:
        """Test encoding of Read Holding Registers PDU."""
        pdu = ReadHoldingRegistersPDU(start_address=1, quantity=10)
        assert pdu.encode_request() == bytearray.fromhex("03 00 01 00 0A")

    def test_read_holding_registers_decode_response(self) -> None:
        """Test decoding of Read Holding Registers PDU."""
        pdu = ReadHoldingRegistersPDU(start_address=1, quantity=2)
        response_bytes = bytearray.fromhex("03 04 00 01 00 02")
        assert pdu.decode_response(response_bytes) == [1, 2]

        # Test with more registers
        pdu = ReadHoldingRegistersPDU(start_address=2, quantity=3)
        response_bytes = bytearray.fromhex("03 06 00 03 00 04 00 05")
        assert pdu.decode_response(response_bytes) == [3, 4, 5]

    def test_read_holding_registers_invalid_response(self) -> None:
        """Test invalid response handling in Read Holding Registers PDU."""
        pdu = ReadHoldingRegistersPDU(start_address=1, quantity=5)

        with pytest.raises(InvalidResponseError, match=r"Expected response to start with function code and byte count"):
            pdu.decode_response(bytearray.fromhex("FF"))

        # Invalid function code
        with pytest.raises(InvalidResponseError, match=r"Invalid function code: expected 0x03, received 0x04"):
            pdu.decode_response(bytearray.fromhex("04 01 05"))

        # Invalid length
        with pytest.raises(InvalidResponseError, match=r"Invalid response PDU length: expected 10, got 5"):
            pdu.decode_response(bytearray.fromhex("03 08 02 03 04"))

        # Invalid register count
        with pytest.raises(InvalidResponseError, match=r"Invalid register count: expected 5, got 4"):
            pdu.decode_response(bytearray.fromhex("03 08 02 03 04 05 FF FF FF FF"))

    def test_decode_request_too_short(self) -> None:
        """Test ReadHoldingRegistersPDU.decode_request raises on too-short request."""
        request = b"\x03\x12"
        with pytest.raises(
            InvalidRequestError, match=r"Expected request to start with function code, address, and quantity"
        ):
            ReadHoldingRegistersPDU.decode_request(request)

    def test_decode_request_invalid_function_code(self) -> None:
        """Test ReadHoldingRegistersPDU.decode_request raises on invalid function code."""
        request = b"\x04\x12\x34\x00\x0a"
        with pytest.raises(InvalidRequestError, match=r"Invalid function code"):
            ReadHoldingRegistersPDU.decode_request(request)


# ============================================================================
# RawReadHoldingRegistersPDU Tests
# ============================================================================


class TestRawReadHoldingRegistersPDU:
    """Tests for RawReadHoldingRegistersPDU."""

    def test_initialization_valid(self) -> None:
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
    def test_initialization_invalid(self, start_address: int, quantity: int, expected_error: str) -> None:
        """Test invalid initialization."""
        with pytest.raises(ValueError, match=expected_error):
            RawReadHoldingRegistersPDU(start_address=start_address, quantity=quantity)

    def test_encode_request(self) -> None:
        """Test encoding request."""
        pdu = RawReadHoldingRegistersPDU(start_address=0x1234, quantity=10)
        encoded = pdu.encode_request()
        assert encoded == b"\x03\x12\x34\x00\x0a"

    def test_decode_response_valid(self) -> None:
        """Test decoding valid response."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x03\x06\x12\x34\x56\x78\x9a\xbc"
        result = pdu.decode_response(response)
        assert result == b"\x12\x34\x56\x78\x9a\xbc"

    def test_decode_response_invalid_function_code(self) -> None:
        """Test decoding response with invalid function code."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x04\x06\x12\x34\x56\x78\x9a\xbc"
        with pytest.raises(InvalidResponseError, match="Invalid function code"):
            pdu.decode_response(response)

    def test_decode_response_invalid_length(self) -> None:
        """Test decoding response with invalid length."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x03\x06\x12\x34"
        with pytest.raises(InvalidResponseError, match="Invalid response PDU length"):
            pdu.decode_response(response)

    def test_decode_response_invalid_register_count(self) -> None:
        """Test decoding response with mismatched register count."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x03\x04\x12\x34\x56\x78"
        with pytest.raises(InvalidResponseError, match="Invalid register count"):
            pdu.decode_response(response)

    def test_decode_response_too_short(self) -> None:
        """Test decoding response that is too short."""
        pdu = RawReadHoldingRegistersPDU(start_address=100, quantity=3)
        response = b"\x03"
        with pytest.raises(InvalidResponseError, match="Expected response to start with function code and byte count"):
            pdu.decode_response(response)

    def test_decode_request_valid(self) -> None:
        """Test decoding valid request."""
        request = b"\x03\x12\x34\x00\x0a"
        pdu = RawReadHoldingRegistersPDU.decode_request(request)
        assert pdu.start_address == 0x1234
        assert pdu.quantity == 10

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decoding request with invalid function code."""
        request = b"\x04\x12\x34\x00\x0a"
        with pytest.raises(InvalidRequestError, match="Invalid function code"):
            RawReadHoldingRegistersPDU.decode_request(request)

    def test_decode_request_too_short(self) -> None:
        """Test decoding request that is too short."""
        request = b"\x03\x12"
        with pytest.raises(
            InvalidRequestError, match="Expected request to start with function code, address, and quantity"
        ):
            RawReadHoldingRegistersPDU.decode_request(request)

    def test_encode_response(self) -> None:
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

    def test_function_code(self) -> None:
        """Test that the function code is correct."""
        pdu = RawReadInputRegistersPDU(start_address=100, quantity=10)
        assert pdu.function_code == 0x04

    def test_encode_request(self) -> None:
        """Test encoding request uses correct function code."""
        pdu = RawReadInputRegistersPDU(start_address=0x1234, quantity=10)
        encoded = pdu.encode_request()
        assert encoded == b"\x04\x12\x34\x00\x0a"

    def test_decode_request(self) -> None:
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

    def test_function_code(self) -> None:
        """Test that the function code is correct."""
        pdu = ReadInputRegistersPDU(start_address=100, quantity=10)
        assert pdu.function_code == 0x04

    def test_encode_request(self) -> None:
        """Test encoding request uses correct function code."""
        pdu = ReadInputRegistersPDU(start_address=0x1234, quantity=10)
        encoded = pdu.encode_request()
        assert encoded == b"\x04\x12\x34\x00\x0a"

    def test_decode_response(self) -> None:
        """Test decoding response."""
        pdu = ReadInputRegistersPDU(start_address=100, quantity=3)
        response = b"\x04\x06\x12\x34\x56\x78\x9a\xbc"
        result = pdu.decode_response(response)
        assert result == [0x1234, 0x5678, 0x9ABC]

    def test_decode_request(self) -> None:
        """Test decoding request."""
        request = b"\x04\x12\x34\x00\x0a"
        pdu = ReadInputRegistersPDU.decode_request(request)
        assert pdu.raw_pdu.start_address == 0x1234
        assert pdu.raw_pdu.quantity == 10

    def test_encode_response(self) -> None:
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
    def test_encode_request_edge_cases(self, address: int, value: int, expected_bytes: bytes) -> None:
        """Test encoding with edge case values."""
        pdu = WriteSingleRegisterPDU(address=address, value=value)
        assert pdu.encode_request() == expected_bytes

    def test_decode_request_valid(self) -> None:
        """Test decoding valid request."""
        request = b"\x06\x12\x34\x56\x78"
        pdu = WriteSingleRegisterPDU.decode_request(request)
        assert pdu.address == 0x1234
        assert pdu.value == 0x5678

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decoding request with invalid function code."""
        request = b"\x03\x12\x34\x56\x78"
        with pytest.raises(InvalidRequestError, match="Invalid function code"):
            WriteSingleRegisterPDU.decode_request(request)

    def test_decode_request_too_short(self) -> None:
        """Test decoding request that is too short."""
        request = b"\x06\x12"
        with pytest.raises(
            InvalidRequestError, match="Expected request to start with function code, address, and value"
        ):
            WriteSingleRegisterPDU.decode_request(request)

    def test_encode_response(self) -> None:
        """Test encoding response."""
        pdu = WriteSingleRegisterPDU(address=0x1234, value=0x5678)
        encoded = pdu.encode_response(0x5678)
        assert encoded == b"\x06\x12\x34\x56\x78"

    def test_rtu_response_data_length(self) -> None:
        """Test RTU response data length constant."""
        assert WriteSingleRegisterPDU.rtu_response_data_length == 4

    def test_write_single_register_validation(self) -> None:
        """Test validation of Write Single Register PDU."""
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535."):
            WriteSingleRegisterPDU(address=-1, value=123)
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535."):
            WriteSingleRegisterPDU(address=65536, value=123)
        with pytest.raises(ValueError, match=r"Value must be between 0 and 65535."):
            WriteSingleRegisterPDU(address=1, value=-1)
        with pytest.raises(ValueError, match=r"Value must be between 0 and 65535."):
            WriteSingleRegisterPDU(address=1, value=65536)

    def test_write_single_register_encode_request(self) -> None:
        """Test encoding of Write Single Register PDU."""
        pdu = WriteSingleRegisterPDU(address=1, value=12345)
        assert pdu.encode_request() == bytearray.fromhex("06 00 01 30 39")

    def test_write_single_register_decode_response(self) -> None:
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

    def test_initialization_valid(self) -> None:
        """Test valid initialization."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=100, content=content)
        assert pdu.start_address == 100
        assert pdu.content == content

    def test_initialization_pads_odd_length(self) -> None:
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
    def test_initialization_invalid(self, start_address: int, content: bytes, expected_error: str) -> None:
        """Test invalid initialization."""
        with pytest.raises(ValueError, match=expected_error):
            RawWriteMultipleRegistersPDU(start_address=start_address, content=content)

    def test_encode_request(self) -> None:
        """Test encoding request."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=0x1000, content=content)
        encoded = pdu.encode_request()
        # Function code (0x10) + address (0x1000) + quantity (2) + byte count (4) + content
        expected = b"\x10\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        assert encoded == expected

    def test_decode_response_valid(self) -> None:
        """Test decoding valid response."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=0x1000, content=content)
        response = b"\x10\x10\x00\x00\x02"
        result = pdu.decode_response(response)
        assert result == 2

    def test_decode_response_invalid(self) -> None:
        """Test decoding invalid response."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=0x1000, content=content)
        response = b"\x10\x10\x00\x00\x03"  # Wrong quantity
        with pytest.raises(InvalidResponseError, match="Device response does not match request"):
            pdu.decode_response(response)

    def test_decode_request_valid(self) -> None:
        """Test decoding valid request."""
        request = b"\x10\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU.decode_request(request)
        assert pdu.start_address == 0x1000
        assert pdu.content == b"\x12\x34\x56\x78"

    def test_decode_request_too_short(self) -> None:
        """Test decoding request that is too short."""
        request = b"\x10\x10\x00"
        with pytest.raises(InvalidRequestError, match="Request too short"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decoding request with invalid function code."""
        request = b"\x03\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        with pytest.raises(InvalidRequestError, match="Invalid function code"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_odd_byte_count(self) -> None:
        """Test decoding request with odd byte count."""
        request = b"\x10\x10\x00\x00\x02\x05\x12\x34\x56\x78\x9a"
        with pytest.raises(InvalidRequestError, match="Byte count must be even"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_mismatched_quantity(self) -> None:
        """Test decoding request with mismatched quantity."""
        request = b"\x10\x10\x00\x00\x03\x04\x12\x34\x56\x78"
        with pytest.raises(InvalidRequestError, match="Invalid register count"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_invalid_data_length(self) -> None:
        """Test decoding request with invalid data length."""
        request = b"\x10\x10\x00\x00\x02\x04\x12\x34"
        with pytest.raises(InvalidRequestError, match="Invalid data length"):
            RawWriteMultipleRegistersPDU.decode_request(request)

    def test_encode_response(self) -> None:
        """Test encoding response."""
        content = b"\x12\x34\x56\x78"
        pdu = RawWriteMultipleRegistersPDU(start_address=0x1000, content=content)
        encoded = pdu.encode_response(2)
        assert encoded == b"\x10\x10\x00\x00\x02"

    def test_rtu_response_data_length(self) -> None:
        """Test RTU response data length constant."""
        assert RawWriteMultipleRegistersPDU.rtu_response_data_length == 5


# ============================================================================
# WriteMultipleRegistersPDU Additional Tests
# ============================================================================


class TestWriteMultipleRegistersPDU:
    """Additional tests for WriteMultipleRegistersPDU."""

    def test_initialization_valid(self) -> None:
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
    def test_initialization_invalid(self, start_address: int, values: list[int], expected_error: str) -> None:
        """Test invalid initialization."""
        with pytest.raises(ValueError, match=expected_error):
            WriteMultipleRegistersPDU(start_address=start_address, values=values)

    def test_write_multiple_registers_validation(self) -> None:
        """Test validation of Write Multiple Registers PDU."""
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535."):
            WriteMultipleRegistersPDU(start_address=-1, values=[123])
        with pytest.raises(ValueError, match=r"Address must be between 0 and 65535."):
            WriteMultipleRegistersPDU(start_address=65536, values=[123])
        with pytest.raises(ValueError, match=r"Number of registers must be between 1 and 123."):
            WriteMultipleRegistersPDU(start_address=1, values=[123] * 124)

        with pytest.raises(ValueError, match=r"Value must be between 0 and 65535: 70000"):
            WriteMultipleRegistersPDU(start_address=1, values=[70000])

    def test_write_multiple_registers_encode_request(self) -> None:
        """Test encoding of Write Multiple Registers PDU."""
        pdu = WriteMultipleRegistersPDU(start_address=1, values=[12345, 255])
        assert pdu.encode_request() == bytearray.fromhex("10 00 01 00 02 04 30 39 00 FF")

    def test_write_multiple_registers_decode_response(self) -> None:
        """Test decoding of Write Multiple Registers PDU."""
        pdu = WriteMultipleRegistersPDU(start_address=1, values=[12345, 255])
        response_bytes = bytearray.fromhex("10 00 01 00 02")
        assert pdu.decode_response(response_bytes) == 2

        with pytest.raises(InvalidResponseError, match="Device response does not match request"):
            pdu.decode_response(bytearray.fromhex("11 00 01 00 02"))

    def test_encode_request(self) -> None:
        """Test encoding request."""
        values = [0x1234, 0x5678]
        pdu = WriteMultipleRegistersPDU(start_address=0x1000, values=values)
        encoded = pdu.encode_request()
        expected = b"\x10\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        assert encoded == expected

    def test_decode_request_valid(self) -> None:
        """Test decoding valid request."""
        request = b"\x10\x10\x00\x00\x02\x04\x12\x34\x56\x78"
        pdu = WriteMultipleRegistersPDU.decode_request(request)
        assert pdu.raw_pdu.start_address == 0x1000
        assert pdu.values == [0x1234, 0x5678]

    def test_encode_response(self) -> None:
        """Test encoding response."""
        values = [0x1234, 0x5678]
        pdu = WriteMultipleRegistersPDU(start_address=0x1000, values=values)
        # The raw_pdu.encode_response should be used
        encoded = pdu.raw_pdu.encode_response(2)
        assert encoded == b"\x10\x10\x00\x00\x02"

    def test_encode_response_delegates(self) -> None:
        """Test that WriteMultipleRegistersPDU.encode_response delegates to RawWriteMultipleRegistersPDU."""
        values = [0x1234, 0x5678]
        pdu = WriteMultipleRegistersPDU(start_address=0x1000, values=values)
        encoded = pdu.encode_response(2)
        assert encoded == b"\x10\x10\x00\x00\x02"

    def test_rtu_response_data_length(self) -> None:
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
    def test_round_trip(self, values: list[int]) -> None:
        """Test encoding and decoding round trip."""
        pdu = WriteMultipleRegistersPDU(start_address=100, values=values)
        request = pdu.encode_request()
        decoded_pdu = WriteMultipleRegistersPDU.decode_request(request)
        assert decoded_pdu.values == values


# ============================================================================
# MaskWriteRegisterPDU Tests
# ============================================================================


class TestMaskWriteRegisterPDU:
    """Tests for MaskWriteRegisterPDU."""

    def test_initialization_valid(self) -> None:
        """Test valid initialization."""
        pdu = MaskWriteRegisterPDU(address=0x0004, and_mask=0xF2F2, or_mask=0x2525)
        assert pdu.address == 0x0004
        assert pdu.and_mask == 0xF2F2
        assert pdu.or_mask == 0x2525

    @pytest.mark.parametrize(
        ("address", "and_mask", "or_mask", "expected_error"),
        [
            (-1, 0xF2F2, 0x2525, "Address must be between 0 and 65535"),
            (65536, 0xF2F2, 0x2525, "Address must be between 0 and 65535"),
            (0x0004, -1, 0x2525, "AND mask must be between 0 and 65535"),
            (0x0004, 65536, 0x2525, "AND mask must be between 0 and 65535"),
            (0x0004, 0xF2F2, -1, "OR mask must be between 0 and 65535"),
            (0x0004, 0xF2F2, 65536, "OR mask must be between 0 and 65535"),
        ],
    )
    def test_initialization_invalid(self, address: int, and_mask: int, or_mask: int, expected_error: str) -> None:
        """Test invalid initialization."""
        with pytest.raises(ValueError, match=expected_error):
            MaskWriteRegisterPDU(address=address, and_mask=and_mask, or_mask=or_mask)

    def test_encode_request(self) -> None:
        """Test encoding request."""
        pdu = MaskWriteRegisterPDU(address=0x0004, and_mask=0xF2F2, or_mask=0x2525)
        # Function code: 0x16, Address: 0x0004, AND mask: 0xF2F2, OR mask: 0x2525
        expected = b"\x16\x00\x04\xf2\xf2\x25\x25"
        assert pdu.encode_request() == expected

    def test_decode_response_valid(self) -> None:
        """Test decoding valid response."""
        pdu = MaskWriteRegisterPDU(address=0x0004, and_mask=0xF2F2, or_mask=0x2525)
        # Response echoes the request: function code, address, AND mask, OR mask
        response = b"\x16\x00\x04\xf2\xf2\x25\x25"
        result = pdu.decode_response(response)
        assert result == (0xF2F2, 0x2525)

    def test_decode_response_invalid_function_code(self) -> None:
        """Test decoding response with invalid function code."""
        pdu = MaskWriteRegisterPDU(address=0x0004, and_mask=0xF2F2, or_mask=0x2525)
        # Invalid function code (0x03 instead of 0x16)
        response = b"\x03\x00\x04\xf2\xf2\x25\x25"
        with pytest.raises(InvalidResponseError, match=r"Invalid function code: expected 0x16, received 0x03"):
            pdu.decode_response(response)

    def test_decode_response_invalid_address(self) -> None:
        """Test decoding response with invalid address."""
        pdu = MaskWriteRegisterPDU(address=0x0004, and_mask=0xF2F2, or_mask=0x2525)
        # Invalid address (0x0005 instead of 0x0004)
        response = b"\x16\x00\x05\xf2\xf2\x25\x25"
        with pytest.raises(InvalidResponseError, match=r"Invalid address: expected 4, received 5"):
            pdu.decode_response(response)

    def test_decode_response_too_short(self) -> None:
        """Test decoding response that is too short."""
        pdu = MaskWriteRegisterPDU(address=0x0004, and_mask=0xF2F2, or_mask=0x2525)
        # Response too short
        response = b"\x16\x00\x04"
        with pytest.raises(
            InvalidResponseError, match=r"Expected response to start with function code, address, AND mask, and OR mask"
        ):
            pdu.decode_response(response)

    def test_rtu_response_data_length(self) -> None:
        """Test RTU response data length constant."""
        assert MaskWriteRegisterPDU.rtu_response_data_length == 6

    @pytest.mark.parametrize(
        ("address", "and_mask", "or_mask"),
        [
            (0, 0, 0),  # Minimum values
            (65535, 65535, 65535),  # Maximum values
            (0x0004, 0xF2F2, 0x2525),  # Example from Modbus spec
            (100, 0xFFFF, 0x0000),  # All bits in AND mask
            (200, 0x0000, 0xFFFF),  # All bits in OR mask
        ],
    )
    def test_encode_decode_round_trip(self, address: int, and_mask: int, or_mask: int) -> None:
        """Test encoding and decoding round trip."""
        pdu = MaskWriteRegisterPDU(address=address, and_mask=and_mask, or_mask=or_mask)
        request = pdu.encode_request()
        # Simulate response (echoes request for mask write)
        response = request
        result = pdu.decode_response(response)
        assert result == (and_mask, or_mask)

    def test_decode_request_valid(self) -> None:
        """Test decoding valid request."""
        request = b"\x16\x00\x04\xf2\xf2\x25\x25"
        pdu = MaskWriteRegisterPDU.decode_request(request)
        assert pdu.address == 0x0004
        assert pdu.and_mask == 0xF2F2
        assert pdu.or_mask == 0x2525

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decoding request with invalid function code."""
        request = b"\x03\x00\x04\xf2\xf2\x25\x25"
        with pytest.raises(InvalidRequestError, match=r"Invalid function code: expected 0x16, received 0x03"):
            MaskWriteRegisterPDU.decode_request(request)

    def test_decode_request_too_short(self) -> None:
        """Test decoding request that is too short."""
        request = b"\x16\x00\x04"
        with pytest.raises(
            InvalidRequestError, match=r"Expected request to start with function code, address, AND mask, and OR mask"
        ):
            MaskWriteRegisterPDU.decode_request(request)

    def test_encode_response(self) -> None:
        """Test encoding response."""
        pdu = MaskWriteRegisterPDU(address=0x0004, and_mask=0xF2F2, or_mask=0x2525)
        response = pdu.encode_response((0xF2F2, 0x2525))
        expected = b"\x16\x00\x04\xf2\xf2\x25\x25"
        assert response == expected


class TestReadWriteMultipleRegistersPDU:
    """Tests for ReadWriteMultipleRegistersPDU."""

    def test_initialization_valid(self) -> None:
        """Test valid initialization."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=100,
            read_quantity=10,
            write_start_address=200,
            write_values=[1, 2, 3, 4, 5],
        )
        assert pdu.read_start_address == 100
        assert pdu.read_quantity == 10
        assert pdu.write_start_address == 200
        assert pdu.write_values == [1, 2, 3, 4, 5]

    @pytest.mark.parametrize(
        ("read_addr", "read_qty", "write_addr", "write_vals", "expected_error"),
        [
            (-1, 10, 100, [1, 2], "Read starting address must be between 0 and 65535"),
            (65536, 10, 100, [1, 2], "Read starting address must be between 0 and 65535"),
            (100, 0, 100, [1, 2], "Read quantity must be between 1 and 125"),
            (100, 126, 100, [1, 2], "Read quantity must be between 1 and 125"),
            (100, 10, -1, [1, 2], "Write starting address must be between 0 and 65535"),
            (100, 10, 65536, [1, 2], "Write starting address must be between 0 and 65535"),
            (100, 10, 100, [], "Number of registers to write must be between 1 and 121"),
            (100, 10, 100, [1] * 122, "Number of registers to write must be between 1 and 121"),
            (100, 10, 100, [65536], "Invalid write value 65536 on index 0"),
            (100, 10, 100, [-1], "Invalid write value -1 on index 0"),
        ],
    )
    def test_initialization_invalid(
        self,
        read_addr: int,
        read_qty: int,
        write_addr: int,
        write_vals: list[int],
        expected_error: str,
    ) -> None:
        """Test invalid initialization parameters."""
        with pytest.raises(ValueError, match=expected_error):
            ReadWriteMultipleRegistersPDU(
                read_start_address=read_addr,
                read_quantity=read_qty,
                write_start_address=write_addr,
                write_values=write_vals,
            )

    def test_encode_request(self) -> None:
        """Test encoding request PDU."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0x0003,
            read_quantity=6,
            write_start_address=0x000E,
            write_values=[0x00FF, 0x00FF, 0x00FF],
        )
        encoded = pdu.encode_request()

        # Expected format:
        # Function code: 0x17
        # Read starting address: 0x0003
        # Quantity to read: 0x0006
        # Write starting address: 0x000E
        # Quantity to write: 0x0003
        # Write byte count: 0x06 (3 registers * 2 bytes)
        # Write data: 0x00FF 0x00FF 0x00FF
        expected = b"\x17\x00\x03\x00\x06\x00\x0e\x00\x03\x06\x00\xff\x00\xff\x00\xff"
        assert encoded == expected

    def test_encode_request_single_write_value(self) -> None:
        """Test encoding request with a single write value."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0,
            read_quantity=1,
            write_start_address=0,
            write_values=[0x1234],
        )
        encoded = pdu.encode_request()

        assert encoded[0] == 0x17  # function code
        assert encoded[-2:] == b"\x12\x34"  # write data

    def test_decode_response_valid(self) -> None:
        """Test decoding a valid response PDU."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0x0003,
            read_quantity=6,
            write_start_address=0x000E,
            write_values=[0x00FF, 0x00FF, 0x00FF],
        )

        # Response format: function code + byte count + data
        # 6 registers = 12 bytes
        response = b"\x17\x0c\x00\x0a\x00\x0b\x00\x0c\x00\x0d\x00\x0e\x00\x0f"
        result = pdu.decode_response(response)

        assert result == [0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F]

    def test_decode_response_single_register(self) -> None:
        """Test decoding response with a single register."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=100,
            read_quantity=1,
            write_start_address=200,
            write_values=[0xABCD],
        )

        response = b"\x17\x02\x12\x34"
        result = pdu.decode_response(response)

        assert result == [0x1234]

    def test_decode_response_invalid_function_code(self) -> None:
        """Test decode_response raises on invalid function code."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0,
            read_quantity=2,
            write_start_address=10,
            write_values=[1, 2],
        )

        response = b"\x03\x04\x00\x01\x00\x02"  # Function code 0x03 instead of 0x17
        with pytest.raises(InvalidResponseError, match=r"Invalid function code: expected 0x17, received 0x03"):
            pdu.decode_response(response)

    def test_decode_response_too_short(self) -> None:
        """Test decode_response raises on response too short."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0,
            read_quantity=2,
            write_start_address=10,
            write_values=[1, 2],
        )

        response = b"\x17"  # Too short
        with pytest.raises(InvalidResponseError, match=r"Expected response to start with function code and byte count"):
            pdu.decode_response(response)

    def test_decode_response_invalid_length(self) -> None:
        """Test decode_response raises on mismatched length."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0,
            read_quantity=2,
            write_start_address=10,
            write_values=[1, 2],
        )

        # Byte count says 4 bytes but only 2 bytes follow
        response = b"\x17\x04\x00\x01"
        with pytest.raises(InvalidResponseError, match=r"Invalid response PDU length"):
            pdu.decode_response(response)

    def test_decode_response_invalid_register_count(self) -> None:
        """Test decode_response raises on wrong register count."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0,
            read_quantity=2,
            write_start_address=10,
            write_values=[1, 2],
        )

        # Says 3 registers (6 bytes) but we expected 2
        response = b"\x17\x06\x00\x01\x00\x02\x00\x03"
        with pytest.raises(InvalidResponseError, match=r"Invalid register count: expected 2, got 3"):
            pdu.decode_response(response)

    def test_decode_response_odd_byte_count(self) -> None:
        """Test decode_response raises on odd byte count."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0,
            read_quantity=2,
            write_start_address=10,
            write_values=[1, 2],
        )

        # Odd byte count (should be even for 16-bit registers)
        response = b"\x17\x05\x00\x01\x00\x02\x00"
        with pytest.raises(InvalidResponseError, match=r"Invalid register count"):
            pdu.decode_response(response)

    def test_decode_request_valid(self) -> None:
        """Test decoding a valid request PDU."""
        # Request format:
        # Function code: 0x17
        # Read starting address: 0x0003
        # Quantity to read: 0x0006
        # Write starting address: 0x000E
        # Quantity to write: 0x0003
        # Write byte count: 0x06
        # Write data: 0x00FF 0x00FF 0x00FF
        request = b"\x17\x00\x03\x00\x06\x00\x0e\x00\x03\x06\x00\xff\x00\xff\x00\xff"

        pdu = ReadWriteMultipleRegistersPDU.decode_request(request)

        assert pdu.read_start_address == 0x0003
        assert pdu.read_quantity == 6
        assert pdu.write_start_address == 0x000E
        assert pdu.write_values == [0x00FF, 0x00FF, 0x00FF]

    def test_decode_request_single_write_value(self) -> None:
        """Test decoding request with single write value."""
        request = b"\x17\x00\x00\x00\x01\x00\x00\x00\x01\x02\x12\x34"

        pdu = ReadWriteMultipleRegistersPDU.decode_request(request)

        assert pdu.read_start_address == 0
        assert pdu.read_quantity == 1
        assert pdu.write_start_address == 0
        assert pdu.write_values == [0x1234]

    def test_decode_request_too_short(self) -> None:
        """Test decode_request raises on request too short."""
        request = b"\x17\x00\x03"  # Too short
        with pytest.raises(InvalidRequestError, match=r"Request too short for Read/Write Multiple Registers"):
            ReadWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decode_request raises on invalid function code."""
        request = b"\x03\x00\x03\x00\x06\x00\x0e\x00\x03\x06\x00\xff\x00\xff\x00\xff"
        with pytest.raises(InvalidRequestError, match=r"Invalid function code: expected 0x17, received 0x03"):
            ReadWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_odd_byte_count(self) -> None:
        """Test decode_request raises on odd write byte count."""
        # Write byte count is 5 (odd) instead of 6
        request = b"\x17\x00\x03\x00\x06\x00\x0e\x00\x03\x05\x00\xff\x00\xff\x00"
        with pytest.raises(InvalidRequestError, match=r"Write byte count must be even for register values"):
            ReadWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_mismatched_quantity(self) -> None:
        """Test decode_request raises on mismatched write quantity."""
        # Write quantity is 3 but byte count is 8 (4 registers)
        request = b"\x17\x00\x03\x00\x06\x00\x0e\x00\x03\x08\x00\xff\x00\xff\x00\xff\x00\xff"
        with pytest.raises(InvalidRequestError, match=r"Invalid write register count: expected 4, got 3"):
            ReadWriteMultipleRegistersPDU.decode_request(request)

    def test_decode_request_invalid_data_length(self) -> None:
        """Test decode_request raises on invalid data length."""
        # Says byte count is 6 but only 2 bytes of data follow (with correct quantity)
        request = b"\x17\x00\x03\x00\x06\x00\x0e\x00\x03\x06\x00\xff"
        with pytest.raises(InvalidRequestError, match=r"Invalid data length: expected 6, got 2"):
            ReadWriteMultipleRegistersPDU.decode_request(request)

    def test_encode_response_valid(self) -> None:
        """Test encoding a valid response PDU."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0x0003,
            read_quantity=6,
            write_start_address=0x000E,
            write_values=[0x00FF, 0x00FF, 0x00FF],
        )

        response = pdu.encode_response([0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F])

        # Expected: function code + byte count (12 for 6 registers) + 6 registers
        expected = b"\x17\x0c\x00\x0a\x00\x0b\x00\x0c\x00\x0d\x00\x0e\x00\x0f"
        assert response == expected

    def test_encode_response_single_value(self) -> None:
        """Test encoding response with single value."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=100,
            read_quantity=1,
            write_start_address=200,
            write_values=[0xABCD],
        )

        response = pdu.encode_response([0x1234])

        # Expected: function code + byte count (2 for 1 register) + 1 register
        assert response == b"\x17\x02\x12\x34"

    def test_encode_response_wrong_count(self) -> None:
        """Test encode_response raises on wrong number of values."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0,
            read_quantity=2,
            write_start_address=10,
            write_values=[1, 2],
        )

        # Trying to encode 3 values when read_quantity is 2
        with pytest.raises(ValueError, match=r"Invalid number of read values: expected 2, got 3"):
            pdu.encode_response([1, 2, 3])

    def test_encode_response_invalid_value_too_high(self) -> None:
        """Test encode_response raises on value too high."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0,
            read_quantity=2,
            write_start_address=10,
            write_values=[1, 2],
        )

        with pytest.raises(ValueError, match=r"Invalid read value 65536 on index 1: must be between 0 and 65535"):
            pdu.encode_response([100, 65536])

    def test_encode_response_invalid_value_negative(self) -> None:
        """Test encode_response raises on negative value."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0,
            read_quantity=2,
            write_start_address=10,
            write_values=[1, 2],
        )

        with pytest.raises(ValueError, match=r"Invalid read value -1 on index 0: must be between 0 and 65535"):
            pdu.encode_response([-1, 100])

    def test_round_trip_encode_decode(self) -> None:
        """Test that encoding and decoding produces the same values."""
        original_pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=50,
            read_quantity=5,
            write_start_address=100,
            write_values=[1, 2, 3, 4, 5],
        )

        # Encode request and decode it back
        encoded_request = original_pdu.encode_request()
        decoded_pdu = ReadWriteMultipleRegistersPDU.decode_request(encoded_request)

        assert decoded_pdu.read_start_address == original_pdu.read_start_address
        assert decoded_pdu.read_quantity == original_pdu.read_quantity
        assert decoded_pdu.write_start_address == original_pdu.write_start_address
        assert decoded_pdu.write_values == original_pdu.write_values

        # Test response round-trip
        read_values = [10, 20, 30, 40, 50]
        encoded_response = original_pdu.encode_response(read_values)
        decoded_values = original_pdu.decode_response(encoded_response)
        assert decoded_values == read_values

    def test_modbus_spec_example_encode_request(self) -> None:
        """Test encoding request using the exact example from Modbus specification.

        Example: Read 6 registers starting at register 4 (address 3),
        and write 3 registers starting at register 15 (address 14).
        """
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0x0003,  # Register 4 (0-indexed)
            read_quantity=0x0006,  # 6 registers
            write_start_address=0x000E,  # Register 15 (0-indexed)
            write_values=[0x00FF, 0x00FF, 0x00FF],  # 3 registers
        )

        encoded = pdu.encode_request()

        # Expected from spec:
        # 17 00 03 00 06 00 0E 00 03 06 00 FF 00 FF 00 FF
        expected = b"\x17\x00\x03\x00\x06\x00\x0e\x00\x03\x06\x00\xff\x00\xff\x00\xff"
        assert encoded == expected

    def test_modbus_spec_example_decode_request(self) -> None:
        """Test decoding request using the exact example from Modbus specification."""
        # Request from spec:
        # 17 00 03 00 06 00 0E 00 03 06 00 FF 00 FF 00 FF
        request = b"\x17\x00\x03\x00\x06\x00\x0e\x00\x03\x06\x00\xff\x00\xff\x00\xff"

        pdu = ReadWriteMultipleRegistersPDU.decode_request(request)

        assert pdu.read_start_address == 0x0003
        assert pdu.read_quantity == 0x0006
        assert pdu.write_start_address == 0x000E
        assert pdu.write_values == [0x00FF, 0x00FF, 0x00FF]

    def test_modbus_spec_example_decode_response(self) -> None:
        """Test decoding response using the exact example from Modbus specification.

        Response contains 6 registers read: 0x00FE, 0x0ACD, 0x0001, 0x0003, 0x000D, 0x00FF
        """
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0x0003,
            read_quantity=0x0006,
            write_start_address=0x000E,
            write_values=[0x00FF, 0x00FF, 0x00FF],
        )

        # Response from spec:
        # 17 0C 00 FE 0A CD 00 01 00 03 00 0D 00 FF
        response = b"\x17\x0c\x00\xfe\x0a\xcd\x00\x01\x00\x03\x00\x0d\x00\xff"

        result = pdu.decode_response(response)

        assert result == [0x00FE, 0x0ACD, 0x0001, 0x0003, 0x000D, 0x00FF]

    def test_modbus_spec_example_encode_response(self) -> None:
        """Test encoding response using the exact example from Modbus specification."""
        pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0x0003,
            read_quantity=0x0006,
            write_start_address=0x000E,
            write_values=[0x00FF, 0x00FF, 0x00FF],
        )

        # Encode response with the values from the spec
        read_values = [0x00FE, 0x0ACD, 0x0001, 0x0003, 0x000D, 0x00FF]
        encoded = pdu.encode_response(read_values)

        # Expected from spec:
        # 17 0C 00 FE 0A CD 00 01 00 03 00 0D 00 FF
        expected = b"\x17\x0c\x00\xfe\x0a\xcd\x00\x01\x00\x03\x00\x0d\x00\xff"
        assert encoded == expected

    def test_modbus_spec_example_full_round_trip(self) -> None:
        """Test full round-trip using the Modbus specification example."""
        # Create PDU with spec example parameters
        original_pdu = ReadWriteMultipleRegistersPDU(
            read_start_address=0x0003,
            read_quantity=0x0006,
            write_start_address=0x000E,
            write_values=[0x00FF, 0x00FF, 0x00FF],
        )

        # Encode and decode request
        request = original_pdu.encode_request()
        decoded_pdu = ReadWriteMultipleRegistersPDU.decode_request(request)

        assert decoded_pdu.read_start_address == original_pdu.read_start_address
        assert decoded_pdu.read_quantity == original_pdu.read_quantity
        assert decoded_pdu.write_start_address == original_pdu.write_start_address
        assert decoded_pdu.write_values == original_pdu.write_values

        # Encode and decode response
        read_values = [0x00FE, 0x0ACD, 0x0001, 0x0003, 0x000D, 0x00FF]
        response = original_pdu.encode_response(read_values)
        decoded_values = original_pdu.decode_response(response)

        assert decoded_values == read_values
