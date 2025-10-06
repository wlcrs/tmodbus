"""Tests for tmodbus/pdu/fifo.py."""

import struct

import pytest
from tmodbus.pdu.fifo import ReadFifoQueuePDU


class TestReadFifoQueuePDU:
    """Tests for ReadFifoQueuePDU."""

    def test_initialization_valid(self) -> None:
        """Test valid initialization."""
        pdu = ReadFifoQueuePDU(address=0x04DE)
        assert pdu.address == 0x04DE
        assert pdu.function_code == 0x18

    @pytest.mark.parametrize(
        ("address", "expected_error"),
        [
            (-1, "Address -1 out of range"),
            (65536, "Address 65536 out of range"),
            (100000, "Address 100000 out of range"),
        ],
    )
    def test_initialization_invalid_address(self, address: int, expected_error: str) -> None:
        """Test initialization with invalid address."""
        with pytest.raises(ValueError, match=expected_error):
            ReadFifoQueuePDU(address=address)

    def test_initialization_valid_boundary_addresses(self) -> None:
        """Test initialization with boundary addresses."""
        pdu_min = ReadFifoQueuePDU(address=0x0000)
        assert pdu_min.address == 0x0000

        pdu_max = ReadFifoQueuePDU(address=0xFFFF)
        assert pdu_max.address == 0xFFFF

    def test_encode_request(self) -> None:
        """Test encoding a request."""
        pdu = ReadFifoQueuePDU(address=0x04DE)
        encoded = pdu.encode_request()

        # Function code (0x18) + Address (0x04DE)
        expected = b"\x18\x04\xde"
        assert encoded == expected

    def test_encode_request_min_address(self) -> None:
        """Test encoding request with minimum address."""
        pdu = ReadFifoQueuePDU(address=0x0000)
        encoded = pdu.encode_request()
        assert encoded == b"\x18\x00\x00"

    def test_encode_request_max_address(self) -> None:
        """Test encoding request with maximum address."""
        pdu = ReadFifoQueuePDU(address=0xFFFF)
        encoded = pdu.encode_request()
        assert encoded == b"\x18\xff\xff"

    def test_decode_request_valid(self) -> None:
        """Test decoding a valid request."""
        request = b"\x18\x04\xde"
        pdu = ReadFifoQueuePDU.decode_request(request)

        assert pdu.address == 0x04DE
        assert pdu.function_code == 0x18

    def test_decode_request_invalid_length_too_short(self) -> None:
        """Test decoding request with invalid length (too short)."""
        request = b"\x18\x04"
        with pytest.raises(ValueError, match=r"Invalid Read FIFO Queue request length: 2. Expected 3"):
            ReadFifoQueuePDU.decode_request(request)

    def test_decode_request_invalid_length_too_long(self) -> None:
        """Test decoding request with invalid length (too long)."""
        request = b"\x18\x04\xde\x00"
        with pytest.raises(ValueError, match=r"Invalid Read FIFO Queue request length: 4. Expected 3"):
            ReadFifoQueuePDU.decode_request(request)

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decoding request with invalid function code."""
        request = b"\x03\x04\xde"
        with pytest.raises(ValueError, match=r"Invalid function code: 0x03. Expected 0x18"):
            ReadFifoQueuePDU.decode_request(request)

    def test_encode_response_valid(self) -> None:
        """Test encoding a valid response."""
        pdu = ReadFifoQueuePDU(address=0x04DE)
        values = [0x01B8, 0x1284]
        encoded = pdu.encode_response(values)

        # Function code (0x18) + Byte count (0x0006 = 2 + 2*2) + FIFO count (0x0002) + Values
        expected = b"\x18\x00\x06\x00\x02\x01\xb8\x12\x84"
        assert encoded == expected

    def test_encode_response_empty_queue(self) -> None:
        """Test encoding response with empty queue."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        values: list[int] = []
        encoded = pdu.encode_response(values)

        # Function code + Byte count (2 bytes for count only) + FIFO count (0)
        expected = b"\x18\x00\x02\x00\x00"
        assert encoded == expected

    def test_encode_response_single_value(self) -> None:
        """Test encoding response with single value."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        values = [0xABCD]
        encoded = pdu.encode_response(values)

        # Function code + Byte count (4 = 2 + 1*2) + FIFO count (1) + Value
        expected = b"\x18\x00\x04\x00\x01\xab\xcd"
        assert encoded == expected

    def test_encode_response_max_count(self) -> None:
        """Test encoding response with maximum count (31)."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        values = list(range(31))
        encoded = pdu.encode_response(values)

        assert encoded[0] == 0x18  # function code
        # Byte count should be 2 + 31*2 = 64 = 0x40
        assert encoded[1:3] == b"\x00\x40"
        # FIFO count should be 31 = 0x001F
        assert encoded[3:5] == b"\x00\x1f"
        assert len(encoded) == 1 + 2 + 64  # function code (1) + byte count field (2) + data (64)

    def test_encode_response_invalid_count_too_high(self) -> None:
        """Test encoding response with count exceeding maximum."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        values = list(range(32))
        with pytest.raises(ValueError, match=r"Count 32 out of range \(0-31\)"):
            pdu.encode_response(values)

    def test_encode_response_invalid_value_too_high(self) -> None:
        """Test encoding response with value exceeding 16-bit range."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        values = [65536]
        with pytest.raises(ValueError, match=r"Value 65536 out of range \(0-65535\)"):
            pdu.encode_response(values)

    def test_encode_response_invalid_value_negative(self) -> None:
        """Test encoding response with negative value."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        values = [-1]
        with pytest.raises(ValueError, match=r"Value -1 out of range \(0-65535\)"):
            pdu.encode_response(values)

    def test_decode_response_valid(self) -> None:
        """Test decoding a valid response."""
        pdu = ReadFifoQueuePDU(address=0x04DE)
        # Function code + Byte count (6) + FIFO count (2) + Values (440, 4740)
        response_data = b"\x18\x00\x06\x00\x02\x01\xb8\x12\x84"
        result = pdu.decode_response(response_data)

        assert result == [0x01B8, 0x1284]

    def test_decode_response_empty_queue(self) -> None:
        """Test decoding response with empty queue."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        response_data = b"\x18\x00\x02\x00\x00"
        result = pdu.decode_response(response_data)

        assert result == []

    def test_decode_response_single_value(self) -> None:
        """Test decoding response with single value."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        response_data = b"\x18\x00\x04\x00\x01\xab\xcd"
        result = pdu.decode_response(response_data)

        assert result == [0xABCD]

    def test_decode_response_max_values(self) -> None:
        """Test decoding response with maximum values (31)."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        # Create response with 31 values
        values = list(range(31))
        byte_count = 2 + 31 * 2  # count (2 bytes) + 31 values (2 bytes each)
        response_data = struct.pack(f">BHH{'H' * 31}", 0x18, byte_count, 31, *values)
        result = pdu.decode_response(response_data)

        assert result == values

    def test_decode_response_invalid_length_too_short(self) -> None:
        """Test decoding response that is too short."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        response_data = b"\x18\x00"
        with pytest.raises(ValueError, match=r"Invalid Read FIFO Queue response length: 2. Minimum expected is 5"):
            pdu.decode_response(response_data)

    def test_decode_response_invalid_function_code(self) -> None:
        """Test decoding response with invalid function code."""
        pdu = ReadFifoQueuePDU(address=0x04DE)
        response_data = b"\x03\x00\x06\x00\x02\x01\xb8\x12\x84"
        with pytest.raises(ValueError, match=r"Invalid function code: 0x03. Expected 0x18"):
            pdu.decode_response(response_data)

    def test_decode_response_invalid_byte_count(self) -> None:
        """Test decoding response with mismatched byte count."""
        pdu = ReadFifoQueuePDU(address=0x04DE)
        # Byte count says 8 but actual data is only 6 bytes (9 total - 3 header = 6)
        response_data = b"\x18\x00\x08\x00\x02\x01\xb8\x12\x84"
        with pytest.raises(ValueError, match=r"Byte count 8 does not match actual data length 6"):
            pdu.decode_response(response_data)

    def test_decode_response_count_mismatch(self) -> None:
        """Test decoding response where FIFO count doesn't match number of values."""
        pdu = ReadFifoQueuePDU(address=0x04DE)
        # FIFO count says 3 but we only have 2 values
        # Byte count = 2 + 2*2 = 6, FIFO count = 3, but only 2 values follow
        response_data = b"\x18\x00\x06\x00\x03\x01\xb8\x12\x84"
        with pytest.raises(ValueError, match=r"FIFO count 3 does not match number of values 2"):
            pdu.decode_response(response_data)

    def test_round_trip_encode_decode_request(self) -> None:
        """Test encoding and decoding request."""
        original_pdu = ReadFifoQueuePDU(address=0x04DE)
        encoded = original_pdu.encode_request()
        decoded_pdu = ReadFifoQueuePDU.decode_request(encoded)

        assert decoded_pdu.address == original_pdu.address
        assert decoded_pdu.function_code == original_pdu.function_code

    def test_round_trip_encode_decode_response(self) -> None:
        """Test encoding and decoding response."""
        pdu = ReadFifoQueuePDU(address=0x04DE)
        original_values = [0x01B8, 0x1284]
        encoded = pdu.encode_response(original_values)
        decoded_response = pdu.decode_response(encoded)

        assert decoded_response == original_values

    @pytest.mark.parametrize(
        "values",
        [
            [],
            [100],
            [1, 2, 3, 4, 5],
            list(range(10)),
            list(range(31)),
        ],
    )
    def test_round_trip_various_counts(self, values: list[int]) -> None:
        """Test round-trip with various counts."""
        pdu = ReadFifoQueuePDU(address=0x1000)
        encoded = pdu.encode_response(values)
        decoded_response = pdu.decode_response(encoded)

        assert decoded_response == values

    def test_modbus_spec_example_encode_request(self) -> None:
        """Test encoding request using the exact example from Modbus specification.

        Example: Read the queue starting at pointer register 1246 (0x04DE).
        """
        pdu = ReadFifoQueuePDU(address=0x04DE)
        encoded = pdu.encode_request()

        # Expected from spec: 18 04 DE
        expected = b"\x18\x04\xde"
        assert encoded == expected

    def test_modbus_spec_example_decode_request(self) -> None:
        """Test decoding request using the exact example from Modbus specification."""
        # Request from spec: 18 04 DE
        request = b"\x18\x04\xde"
        pdu = ReadFifoQueuePDU.decode_request(request)

        assert pdu.address == 0x04DE
        assert pdu.function_code == 0x18

    def test_modbus_spec_example_decode_response(self) -> None:
        """Test decoding response using the exact example from Modbus specification.

        Response contains queue count of 2, with values:
        - 1247: 440 (0x01B8)
        - 1248: 4740 (0x1284)
        """
        pdu = ReadFifoQueuePDU(address=0x04DE)

        # Response from spec: 18 00 06 00 02 01 B8 12 84
        response = b"\x18\x00\x06\x00\x02\x01\xb8\x12\x84"
        result = pdu.decode_response(response)

        assert result == [0x01B8, 0x1284]  # 440 and 4740 in decimal

    def test_modbus_spec_example_encode_response(self) -> None:
        """Test encoding response using the exact example from Modbus specification."""
        pdu = ReadFifoQueuePDU(address=0x04DE)
        values = [0x01B8, 0x1284]
        encoded = pdu.encode_response(values)

        # Expected from spec: 18 00 06 00 02 01 B8 12 84
        expected = b"\x18\x00\x06\x00\x02\x01\xb8\x12\x84"
        assert encoded == expected

    def test_modbus_spec_example_full_round_trip(self) -> None:
        """Test full round-trip using the Modbus specification example."""
        # Create PDU with spec example parameters
        original_pdu = ReadFifoQueuePDU(address=0x04DE)

        # Encode and decode request
        request = original_pdu.encode_request()
        decoded_pdu = ReadFifoQueuePDU.decode_request(request)

        assert decoded_pdu.address == original_pdu.address
        assert decoded_pdu.function_code == original_pdu.function_code

        # Encode and decode response
        values = [0x01B8, 0x1284]
        response = original_pdu.encode_response(values)
        decoded_response = original_pdu.decode_response(response)

        assert decoded_response == values
