"""Tests for tmodbus/pdu/file.py."""

import struct

import pytest
from tmodbus.exceptions import InvalidRequestError, InvalidResponseError
from tmodbus.pdu.file import (
    FileRecord,
    FileRecordRequest,
    ReadFileRecordPDU,
    WriteFileRecordPDU,
)


class TestReadFileRecordPDU:
    """Tests for ReadFileRecordPDU."""

    def test_function_code(self) -> None:
        """Test that the function code is correct."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)
        assert pdu.function_code == 0x14

    def test_encode_request_single_record(self) -> None:
        """Test encoding a single file record request."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)
        encoded = pdu.encode_request()

        # Should be: function code + byte count + reference type + file number + record number + record length
        # 0x14 + 0x07 + 0x06 + 0x0004 + 0x0001 + 0x0002
        expected = b"\x14\x07\x06\x00\x04\x00\x01\x00\x02"
        assert encoded == expected

    def test_encode_request_modbus_spec_example(self) -> None:
        """Test encoding using Modbus specification example.

        From Modbus spec section 6.14 (Read File Record):
        Request to read two records from file 4:
        - Record 1, length 2 registers
        - Record 8, length 1 register
        """
        requests = [
            FileRecordRequest(file_number=4, record_number=1, record_length=2),
            FileRecordRequest(file_number=3, record_number=9, record_length=2),
        ]
        pdu = ReadFileRecordPDU(requests)
        encoded = pdu.encode_request()

        # Expected format:
        # Function code: 0x14
        # Byte count: 0x0E (14 bytes - 2 sub-requests * 7 bytes each)
        # Sub-request 1: 0x06 (ref type) + 0x0004 (file) + 0x0001 (record) + 0x0002 (length)
        # Sub-request 2: 0x06 (ref type) + 0x0003 (file) + 0x0009 (record) + 0x0002 (length)
        expected = b"\x14\x0e\x06\x00\x04\x00\x01\x00\x02\x06\x00\x03\x00\x09\x00\x02"
        assert encoded == expected

        # Verify the structure is correct
        assert encoded[0] == 0x14  # function code
        assert encoded[1] == 0x0E  # byte count (14 bytes)

        # First sub-request
        assert encoded[2] == 0x06  # reference type
        assert struct.unpack(">H", encoded[3:5])[0] == 4  # file number
        assert struct.unpack(">H", encoded[5:7])[0] == 1  # record number
        assert struct.unpack(">H", encoded[7:9])[0] == 2  # record length

        # Second sub-request
        assert encoded[9] == 0x06  # reference type
        assert struct.unpack(">H", encoded[10:12])[0] == 3  # file number
        assert struct.unpack(">H", encoded[12:14])[0] == 9  # record number
        assert struct.unpack(">H", encoded[14:16])[0] == 2  # record length

    def test_encode_request_multiple_records(self) -> None:
        """Test encoding multiple file record requests."""
        requests = [
            FileRecordRequest(file_number=1, record_number=0, record_length=10),
            FileRecordRequest(file_number=2, record_number=5, record_length=5),
            FileRecordRequest(file_number=3, record_number=100, record_length=1),
        ]
        pdu = ReadFileRecordPDU(requests)
        encoded = pdu.encode_request()

        # 3 requests * 7 bytes = 21 bytes
        assert encoded[0] == 0x14  # function code
        assert encoded[1] == 21  # byte count

    def test_validation_file_number_invalid(self) -> None:
        """Test that invalid file numbers raise InvalidRequestError."""
        with pytest.raises(InvalidRequestError, match="File number must be between 0 and 65535"):
            ReadFileRecordPDU([FileRecordRequest(file_number=-1, record_number=0, record_length=1)])

        with pytest.raises(InvalidRequestError, match="File number must be between 0 and 65535"):
            ReadFileRecordPDU([FileRecordRequest(file_number=0x10000, record_number=0, record_length=1)])

    def test_validation_record_number_invalid(self) -> None:
        """Test that invalid record numbers raise InvalidRequestError."""
        with pytest.raises(InvalidRequestError, match="Record number must be between 0 and 9999"):
            ReadFileRecordPDU([FileRecordRequest(file_number=0, record_number=-1, record_length=1)])

        with pytest.raises(InvalidRequestError, match="Record number must be between 0 and 9999"):
            ReadFileRecordPDU([FileRecordRequest(file_number=0, record_number=10000, record_length=1)])

    def test_validation_record_length_invalid(self) -> None:
        """Test that invalid record lengths raise InvalidRequestError."""
        with pytest.raises(InvalidRequestError, match="Record length must be between 1 and 65535"):
            ReadFileRecordPDU([FileRecordRequest(file_number=0, record_number=0, record_length=0)])

        with pytest.raises(InvalidRequestError, match="Record length must be between 1 and 65535"):
            ReadFileRecordPDU([FileRecordRequest(file_number=0, record_number=0, record_length=0x10000)])

    def test_decode_response_valid_single_record(self) -> None:
        """Test decoding a valid response with a single record."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)

        # Response: function code + byte count + file response length + ref type + data (4 bytes for 2 registers)
        response = b"\x14\x06\x05\x06\x0d\xfe\x00\x20"
        result = pdu.decode_response(response)

        assert len(result) == 1
        assert result[0] == b"\x0d\xfe\x00\x20"

    def test_decode_response_modbus_spec_example(self) -> None:
        """Test decoding using Modbus specification example.

        Response to the spec example with two records.
        """
        requests = [
            FileRecordRequest(file_number=4, record_number=1, record_length=2),
            FileRecordRequest(file_number=4, record_number=8, record_length=1),
        ]
        pdu = ReadFileRecordPDU(requests)

        # Response format:
        # Function code: 0x14
        # Byte count: 0x0C (12 bytes total response data)
        # File resp length 1: 0x02 (2 registers = 4 bytes) + ref type 0x06 + data (4 bytes)
        # File resp length 2: 0x01 (1 register = 2 bytes) + ref type 0x06 + data (2 bytes)
        response = b"\x14\x0c\x05\x06\x0d\xfe\x00\x20\x05\x06\x33\xcd\x00\x40"
        result = pdu.decode_response(response)

        assert len(result) == 2
        assert result[0] == b"\x0d\xfe\x00\x20"  # First record data (2 registers)
        assert result[1] == b"\x33\xcd\x00\x40"  # Second record data (1 register)

    def test_decode_response_invalid_function_code(self) -> None:
        """Test decode_response raises InvalidResponseError on wrong function code."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)

        response = b"\x15\x06\x02\x06\x0d\xfe\x00\x20\x00"
        with pytest.raises(InvalidResponseError, match="Invalid function code"):
            pdu.decode_response(response)

    def test_decode_response_struct_error(self) -> None:
        """Test decode_response raises InvalidResponseError on malformed header."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)

        # Too short to unpack
        response = b"\x14"
        with pytest.raises(InvalidResponseError, match="Expected response to start with function code and byte count"):
            pdu.decode_response(response)

    def test_decode_response_invalid_byte_count(self) -> None:
        """Test decode_response raises InvalidResponseError on mismatched byte count."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)

        # Byte count says 10 but only 6 bytes follow
        response = b"\x14\x0a\x02\x06\x0d\xfe\x00\x20"
        with pytest.raises(InvalidResponseError, match="Response length"):
            pdu.decode_response(response)

    def test_decode_response_invalid_reference_type(self) -> None:
        """Test decode_response raises InvalidResponseError on wrong reference type."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)

        # Reference type is 0x07 instead of 0x06
        response = b"\x14\x06\x02\x07\x0d\xfe\x00\x20"
        with pytest.raises(InvalidResponseError, match="Invalid reference type"):
            pdu.decode_response(response)

    def test_encode_response_even_length_record(self) -> None:
        """Test encode_response does not pad even-length records."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)

        # Provide even-length data (4 bytes) - should not be padded
        even_length_data = b"\x0d\xfe\x00\x20"
        encoded = pdu.encode_response([even_length_data])

        # Format: function code + byte_count + file_response_length + reference_type + data
        # \x14 + \x06 + \x02 + \x06 + \x0d\xfe\x00\x20
        assert encoded == b"\x14\x06\x05\x06\x0d\xfe\x00\x20"

    def test_decode_request_valid_single_request(self) -> None:
        """Test decode_request with a valid single request."""
        # Function code + byte count + reference type + file + record + length
        # 0x14 + 0x07 + 0x06 + 0x0004 + 0x0001 + 0x0002
        request = b"\x14\x07\x06\x00\x04\x00\x01\x00\x02"

        pdu = ReadFileRecordPDU.decode_request(request)

        assert pdu.function_code == 0x14
        assert len(pdu.requests) == 1
        assert pdu.requests[0].file_number == 4
        assert pdu.requests[0].record_number == 1
        assert pdu.requests[0].record_length == 2

    def test_decode_request_valid_multiple_requests(self) -> None:
        """Test decode_request with multiple valid requests."""
        # Two requests
        request = b"\x14\x0e\x06\x00\x04\x00\x01\x00\x02\x06\x00\x03\x00\x09\x00\x02"

        pdu = ReadFileRecordPDU.decode_request(request)

        assert pdu.function_code == 0x14
        assert len(pdu.requests) == 2
        assert pdu.requests[0].file_number == 4
        assert pdu.requests[0].record_number == 1
        assert pdu.requests[0].record_length == 2
        assert pdu.requests[1].file_number == 3
        assert pdu.requests[1].record_number == 9
        assert pdu.requests[1].record_length == 2

    def test_decode_request_modbus_spec_example(self) -> None:
        """Test decode_request using Modbus specification example."""
        # From Modbus spec: Read file 4, starting at record 1, for 2 registers
        request = b"\x14\x07\x06\x00\x04\x00\x01\x00\x02"

        pdu = ReadFileRecordPDU.decode_request(request)

        assert pdu.function_code == 0x14
        assert len(pdu.requests) == 1
        assert pdu.requests[0].file_number == 4
        assert pdu.requests[0].record_number == 1
        assert pdu.requests[0].record_length == 2

    def test_decode_request_invalid_function_code(self) -> None:
        """Test decode_request raises InvalidRequestError on wrong function code."""
        request = b"\x15\x07\x06\x00\x04\x00\x01\x00\x02"  # 0x15 instead of 0x14

        with pytest.raises(InvalidRequestError, match="Invalid function code"):
            ReadFileRecordPDU.decode_request(request)

    def test_decode_request_struct_error_header(self) -> None:
        """Test decode_request raises error on malformed header."""
        request = b"\x14"  # Too short

        with pytest.raises(InvalidRequestError, match="Expected request to start with function code and byte count"):
            ReadFileRecordPDU.decode_request(request)

    def test_decode_request_invalid_file_record_request_too_short(self) -> None:
        """Test decode_request raises error when file record request is too short."""
        request = b"\x14\x03\x06\x00\x04"

        with pytest.raises(InvalidRequestError, match="Failed to unpack file record request"):
            ReadFileRecordPDU.decode_request(request)

    def test_decode_request_invalid_byte_count_short(self) -> None:
        """Test decode_request raises error when byte count is too large."""
        # Byte count says 10 bytes but only 7 bytes of data follow
        request = b"\x14\x0a\x06\x00\x04\x00\x01\x00\x02"

        with pytest.raises(InvalidRequestError, match=r"Request length \d+ is not equal to expected \d+"):
            ReadFileRecordPDU.decode_request(request)

    def test_decode_request_invalid_reference_type(self) -> None:
        """Test decode_request raises error on wrong reference type."""
        request = b"\x14\x07\x07\x00\x04\x00\x01\x00\x02"  # 0x07 instead of 0x06

        with pytest.raises(InvalidRequestError, match=r"Invalid reference type.*"):
            ReadFileRecordPDU.decode_request(request)

    def test_decode_response_sub_record_struct_error(self) -> None:
        """Test decode_response raises InvalidResponseError on malformed sub-record (lines 128-130)."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)

        # Response with correct byte count but incomplete sub-record data to trigger struct.error
        response = b"\x14\x01\x06"  # Byte count=4, but data cuts off mid-unpack

        with pytest.raises(InvalidResponseError, match="Failed to unpack"):
            pdu.decode_response(response)

    def test_decode_response_not_enough_data_for_record(self) -> None:
        """Test decode_response raises InvalidResponseError when data is insufficient (lines 140-141)."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)

        # Says 4 bytes of data but only provides 2 (file_response_length = 0x06 means 4 bytes of data)
        response = b"\x14\x04\x06\x06\x0d\xfe"  # Missing 2 bytes of data

        with pytest.raises(InvalidResponseError, match="Not enough data"):
            pdu.decode_response(response)

    def test_decode_response_extra_bytes_after_records(self) -> None:
        """Test decode_response raises InvalidResponseError with extra bytes (lines 148-149)."""
        requests = [FileRecordRequest(file_number=4, record_number=1, record_length=2)]
        pdu = ReadFileRecordPDU(requests)

        # Valid response data but with offset mismatch at the end
        # Byte count indicates 10 bytes, causing offset != end_offset
        response = b"\x14\x0a\x06\x06\x0d\xfe\x00\x20\x06\x06\x0d\xfe"

        with pytest.raises(InvalidResponseError, match=r"(Failed to unpack|Invalid reference type).*"):
            pdu.decode_response(response)


class TestWriteFileRecordPDU:
    """Tests for WriteFileRecordPDU."""

    def test_function_code(self) -> None:
        """Test that the function code is correct."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)
        assert pdu.function_code == 0x15

    def test_encode_request_single_record(self) -> None:
        """Test encoding a single file record write request."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)
        encoded = pdu.encode_request()

        # Expected: function code + byte count + ref type + file + record + length + data
        # 0x15 + 0x0B + 0x06 + 0x0004 + 0x0007 + 0x0002 + 0x06AF04BE
        expected = b"\x15\x0b\x06\x00\x04\x00\x07\x00\x02\x06\xaf\x04\xbe"
        assert encoded == expected

    def test_encode_request_modbus_spec_example(self) -> None:
        """Test encoding using Modbus specification example.

        From Modbus spec section 6.15 (Write File Record):
        Write to file 4, record 7, with 2 registers of data.
        """
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe\x10\x0d")]
        pdu = WriteFileRecordPDU(file_records=records)
        encoded = pdu.encode_request()

        # Expected format:
        # Function code: 0x15
        # Byte count: 0x0D (13 bytes)
        # Reference type: 0x06
        # File number: 0x0004
        # Record number: 0x0007
        # Record length: 0x0003 (2 registers)
        # Data: 0x06AF04BE100D  # noqa: ERA001
        expected = b"\x15\x0d\x06\x00\x04\x00\x07\x00\x03\x06\xaf\x04\xbe\x10\x0d"
        assert encoded == expected

        # Verify structure
        assert encoded[0] == 0x15  # function code
        assert encoded[1] == 0x0D  # byte count (13 bytes)
        assert encoded[2] == 0x06  # reference type
        assert struct.unpack(">H", encoded[3:5])[0] == 4  # file number
        assert struct.unpack(">H", encoded[5:7])[0] == 7  # record number
        assert struct.unpack(">H", encoded[7:9])[0] == 3  # record length (in registers)
        assert encoded[9:15] == b"\x06\xaf\x04\xbe\x10\x0d"  # data

    def test_encode_request_multiple_records(self) -> None:
        """Test encoding multiple file record write requests."""
        records = [
            FileRecord(file_number=1, record_number=0, data=b"\x00\x01\x00\x02"),
            FileRecord(file_number=2, record_number=5, data=b"\x00\x03"),
        ]
        pdu = WriteFileRecordPDU(file_records=records)
        encoded = pdu.encode_request()

        # First record: 7 bytes header + 4 bytes data = 11 bytes
        # Second record: 7 bytes header + 2 bytes data = 9 bytes
        # Total: 20 bytes
        assert encoded[0] == 0x15  # function code
        assert encoded[1] == 20  # byte count

    def test_encode_request_odd_length_data(self) -> None:
        """Test encoding with odd-length data (should be padded)."""
        records = [FileRecord(file_number=1, record_number=0, data=b"\x00\x01\x02")]
        pdu = WriteFileRecordPDU(file_records=records)
        encoded = pdu.encode_request()

        # Odd length (3 bytes) should be padded to 4 bytes (2 registers)
        # Header: 7 bytes, Data: 4 bytes (3 + 1 padding)
        assert encoded[1] == 11  # byte count
        assert struct.unpack(">H", encoded[7:9])[0] == 2  # record length is 2 registers

    def test_validation_file_number_invalid(self) -> None:
        """Test that invalid file numbers raise InvalidRequestError."""
        with pytest.raises(InvalidRequestError, match="File number must be between 0 and 65535"):
            WriteFileRecordPDU(file_records=[FileRecord(file_number=-1, record_number=0, data=b"\x00\x01")])

        with pytest.raises(InvalidRequestError, match="File number must be between 0 and 65535"):
            WriteFileRecordPDU(file_records=[FileRecord(file_number=0x10000, record_number=0, data=b"\x00\x01")])

    def test_validation_record_number_invalid(self) -> None:
        """Test that invalid record numbers raise InvalidRequestError."""
        with pytest.raises(InvalidRequestError, match="Record number must be between 0 and 9999"):
            WriteFileRecordPDU(file_records=[FileRecord(file_number=0, record_number=-1, data=b"\x00\x01")])

        with pytest.raises(InvalidRequestError, match="Record number must be between 0 and 9999"):
            WriteFileRecordPDU(file_records=[FileRecord(file_number=0, record_number=10000, data=b"\x00\x01")])

    def test_validation_data_length_invalid(self) -> None:
        """Test that invalid data lengths raise InvalidRequestError."""
        # Data length must not exceed 65535 bytes
        with pytest.raises(InvalidRequestError, match="Record data length must be between 0 and 65535 bytes"):
            WriteFileRecordPDU(file_records=[FileRecord(file_number=0, record_number=0, data=b"\x00" * 65536)])

    def test_decode_response_valid_single_record(self) -> None:
        """Test decoding a valid response with a single record."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)

        # Response echoes back the request
        response = b"\x15\x0b\x06\x00\x04\x00\x07\x00\x02\x06\xaf\x04\xbe"
        result = pdu.decode_response(response)

        assert len(result) == 1
        assert result[0].file_number == 4
        assert result[0].record_number == 7
        assert result[0].data == b"\x06\xaf\x04\xbe"

    def test_decode_response_modbus_spec_example(self) -> None:
        """Test decoding using Modbus specification example.

        Response echoes the request.
        """
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)

        # Response format (same as request):
        response = b"\x15\x0b\x06\x00\x04\x00\x07\x00\x02\x06\xaf\x04\xbe"
        result = pdu.decode_response(response)

        assert len(result) == 1
        assert result[0].file_number == 4
        assert result[0].record_number == 7
        assert result[0].data == b"\x06\xaf\x04\xbe"

    def test_decode_response_multiple_records(self) -> None:
        """Test decoding a response with multiple records."""
        records = [
            FileRecord(file_number=1, record_number=0, data=b"\x00\x01\x00\x02"),
            FileRecord(file_number=2, record_number=5, data=b"\x00\x03\x00\x04"),
        ]
        pdu = WriteFileRecordPDU(file_records=records)

        response = b"\x15\x16\x06\x00\x01\x00\x00\x00\x02\x00\x01\x00\x02\x06\x00\x02\x00\x05\x00\x02\x00\x03\x00\x04"
        result = pdu.decode_response(response)

        assert len(result) == 2
        assert result[0].file_number == 1
        assert result[0].record_number == 0
        assert result[0].data == b"\x00\x01\x00\x02"
        assert result[1].file_number == 2
        assert result[1].record_number == 5
        assert result[1].data == b"\x00\x03\x00\x04"

    def test_decode_response_invalid_function_code(self) -> None:
        """Test decode_response raises InvalidResponseError on wrong function code."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)

        response = b"\x14\x0b\x06\x00\x04\x00\x07\x00\x02\x06\xaf\x04\xbe"
        with pytest.raises(InvalidResponseError, match="Invalid function code"):
            pdu.decode_response(response)

    def test_decode_response_struct_error(self) -> None:
        """Test decode_response raises InvalidResponseError on malformed header."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)

        # Too short to unpack
        response = b"\x15"
        with pytest.raises(InvalidResponseError, match="Expected response to start with function code and byte count"):
            pdu.decode_response(response)

    def test_decode_response_invalid_byte_count(self) -> None:
        """Test decode_response raises InvalidResponseError on mismatched byte count."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)

        # Byte count says 15 but only 11 bytes follow
        response = b"\x15\x0f\x06\x00\x04\x00\x07\x00\x02\x06\xaf\x04\xbe"
        with pytest.raises(InvalidResponseError, match="Response length"):
            pdu.decode_response(response)

    def test_decode_response_invalid_reference_type(self) -> None:
        """Test decode_response raises InvalidResponseError on wrong reference type."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)

        # Reference type is 0x07 instead of 0x06
        response = b"\x15\x0b\x07\x00\x04\x00\x07\x00\x02\x06\xaf\x04\xbe"
        with pytest.raises(InvalidResponseError, match="Invalid reference type"):
            pdu.decode_response(response)

    def test_decode_response_not_enough_data(self) -> None:
        """Test decode_response raises InvalidResponseError when data is insufficient."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)

        # Says record length is 2 registers (4 bytes) but only 2 bytes provided
        response = b"\x15\x09\x06\x00\x04\x00\x07\x00\x02\x06\xaf"
        with pytest.raises(InvalidResponseError, match="Not enough data for the specified record length"):
            pdu.decode_response(response)

    def test_decode_response_sub_record_struct_error(self) -> None:
        """Test decode_response raises InvalidResponseError on malformed sub-record."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)

        # Incomplete sub-record header
        response = b"\x15\x04\x06\x00\x04\x00"
        with pytest.raises(InvalidResponseError, match="Failed to unpack file record header"):
            pdu.decode_response(response)

    def test_encode_response(self) -> None:
        """Test encode_response method."""
        records = [FileRecord(file_number=4, record_number=7, data=b"\x06\xaf\x04\xbe")]
        pdu = WriteFileRecordPDU(file_records=records)

        # encode_response should produce the same output as encode_request for this PDU
        encoded = pdu.encode_response(records)

        expected = b"\x15\x0b\x06\x00\x04\x00\x07\x00\x02\x06\xaf\x04\xbe"
        assert encoded == expected

    def test_decode_request_valid(self) -> None:
        """Test decode_request with valid request data."""
        # Valid request from spec example
        request = b"\x15\x0b\x06\x00\x04\x00\x07\x00\x02\x06\xaf\x04\xbe"

        pdu = WriteFileRecordPDU.decode_request(request)

        assert pdu.function_code == 0x15
        assert len(pdu.file_records) == 1
        assert pdu.file_records[0].file_number == 4
        assert pdu.file_records[0].record_number == 7
        assert pdu.file_records[0].data == b"\x06\xaf\x04\xbe"
