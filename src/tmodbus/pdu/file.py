"""PDU's for file record operations."""

import struct
from dataclasses import dataclass
from typing import Self

from tmodbus.exceptions import InvalidRequestError, InvalidResponseError

from .base import BasePDU

FILE_RECORD_REFERENCE_TYPE = 0x06  # reference type for file records

# Modbus caps the request byte count of these function codes at a single byte. The
# specification limits Read File Record (0x14) to 0xF5 and Write File Record (0x15)
# to 0xFB bytes.
MAX_READ_FILE_RECORD_BYTE_COUNT = 0xF5
MAX_WRITE_FILE_RECORD_BYTE_COUNT = 0xFB


@dataclass(frozen=True)
class FileRecordRequest:
    """Data structure for a single file record request."""

    file_number: int
    record_number: int
    record_length: int


SUB_REQUEST_STRUCT = struct.Struct(
    ">BHHH"
)  # reference type (1 byte), file number (2 bytes), record number (2 bytes), record length (2 bytes)


class ReadFileRecordPDU(BasePDU[list[bytes]]):
    """PDU for Read File Record (function code 0x14)."""

    function_code = 0x14
    requests: list[FileRecordRequest]

    def __init__(self, requests: list[FileRecordRequest]) -> None:
        """Initialize ReadFileRecordPDU.

        Args:
            requests: List of FileRecordRequest instances to request.

        Raises:
            ValueError: If any record is invalid.

        """
        for request in requests:
            if not (0 <= request.file_number <= 0xFFFF):
                msg = "File number must be between 0 and 65535."
                raise ValueError(msg)
            if not (0 <= request.record_number <= 9999):
                msg = "Record number must be between 0 and 9999."
                raise ValueError(msg)
            if not (1 <= request.record_length <= 0xFFFF):
                msg = "Record length must be between 1 and 65535."
                raise ValueError(msg)

        if not requests:
            msg = "At least one file record request is required."
            raise ValueError(msg)

        byte_count = len(requests) * SUB_REQUEST_STRUCT.size
        if byte_count > MAX_READ_FILE_RECORD_BYTE_COUNT:
            msg = (
                f"Read File Record request byte count {byte_count} exceeds the "
                f"maximum of {MAX_READ_FILE_RECORD_BYTE_COUNT}."
            )
            raise ValueError(msg)

        self.requests = requests

    def encode_request(self) -> bytes:
        """Encode the PDU into bytes.

        Returns:
            Encoded bytes of the PDU.

        """
        byte_count = len(self.requests) * SUB_REQUEST_STRUCT.size  # 7 bytes per request
        pdu = struct.pack(">BB", self.function_code, byte_count)
        for request in self.requests:
            pdu += SUB_REQUEST_STRUCT.pack(
                FILE_RECORD_REFERENCE_TYPE,
                request.file_number,
                request.record_number,
                request.record_length,
            )

        return pdu

    def encode_response(self, file_records: list[bytes]) -> bytes:
        """Encode the response PDU.

        Returns:
            Encoded bytes of the PDU.

        """
        records_bytes = b""
        for record in file_records:
            record_length = len(record) + 1
            records_bytes += struct.pack(">BB", record_length, FILE_RECORD_REFERENCE_TYPE) + record

        byte_count = len(records_bytes)
        return struct.pack(">BB", self.function_code, byte_count) + records_bytes

    def decode_response(self, response: bytes) -> list[bytes]:
        """Decode the response PDU.

        Args:
            response: Bytes to decode.

        Returns:
            List of bytes: every entry corresponds to a requested record.

        Raises:
            InvalidResponseError: If the response is invalid.

        """
        # response format: function code (1 byte) + byte count (1 byte)
        #                  + [reference type (1 byte) + record length (1 byte) + data]...

        try:
            function_code, byte_count = struct.unpack_from(">BB", response, 0)
        except struct.error as e:
            msg = "Expected response to start with function code and byte count"
            raise InvalidResponseError(msg, response_bytes=response) from e

        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:#04x}, received {function_code:#04x}"
            raise InvalidResponseError(msg, response_bytes=response)

        if len(response) - 2 != byte_count:
            msg = f"Response length {len(response)} is not equal to expected {2 + byte_count}"
            raise InvalidResponseError(msg, response_bytes=response)

        records: list[bytes] = []
        offset = 2

        while offset < len(response):
            try:
                file_response_length, reference_type = struct.unpack_from(">BB", response, offset)
            except struct.error as e:
                msg = "Failed to unpack reference type and record length"
                raise InvalidResponseError(msg, response_bytes=response) from e

            if reference_type != FILE_RECORD_REFERENCE_TYPE:
                msg = (
                    f"Invalid reference type: expected {FILE_RECORD_REFERENCE_TYPE:#04x}, "
                    f"received {reference_type:#04x}"
                )
                raise InvalidResponseError(msg, response_bytes=response)

            data_start = offset + 2  # move past length and reference type
            data_end = data_start + file_response_length - 1  # reference type is included in length

            if data_end > len(response):
                msg = "Not enough data for the specified record length"
                raise InvalidResponseError(msg, response_bytes=response)

            records.append(response[data_start:data_end])

            offset = data_end

        return records

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode the request PDU.

        Args:
            request: Bytes to decode.

        Returns:
            List of FileRecordRequest instances as requested.

        Raises:
            InvalidRequestError: If the request is invalid.

        """
        try:
            function_code, byte_count = struct.unpack_from(">BB", request, 0)
        except struct.error as e:
            msg = "Expected request to start with function code and byte count"
            raise InvalidRequestError(msg, request_bytes=request) from e

        if function_code != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {function_code:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        if len(request) - 2 != byte_count:
            msg = f"Request length {len(request)} is not equal to expected {2 + byte_count}"
            raise InvalidRequestError(msg, request_bytes=request)

        requests: list[FileRecordRequest] = []
        offset = 2

        while offset < len(request):
            try:
                reference_type, file_number, record_number, record_length = SUB_REQUEST_STRUCT.unpack_from(
                    request, offset
                )
            except struct.error as e:
                msg = "Failed to unpack file record request"
                raise InvalidRequestError(msg, request_bytes=request) from e

            if reference_type != FILE_RECORD_REFERENCE_TYPE:
                msg = (
                    f"Invalid reference type: expected {FILE_RECORD_REFERENCE_TYPE:#04x}, "
                    f"received {reference_type:#04x}"
                )
                raise InvalidRequestError(msg, request_bytes=request)

            requests.append(FileRecordRequest(file_number, record_number, record_length))

            offset += SUB_REQUEST_STRUCT.size

        try:
            return cls(requests)
        except ValueError as e:
            raise InvalidRequestError(str(e), request_bytes=request) from e

    @classmethod
    def get_expected_request_data_length(cls, data: bytes) -> int:
        """Get the expected number of bytes for the data part of the request PDU."""
        return 1 + data[0]

@dataclass(frozen=True)
class FileRecord:
    """Data structure for Write File Record response."""

    file_number: int
    record_number: int
    data: bytes


@dataclass(frozen=True)
class WriteFileRecordPDU(BasePDU[list[FileRecord]]):
    """PDU for Write File Record (function code 0x15)."""

    function_code = 0x15

    file_records: list[FileRecord]

    def __post_init__(self) -> None:
        """Validate file records after initialization."""
        for record in self.file_records:
            if not (0 <= record.file_number <= 0xFFFF):
                msg = "File number must be between 0 and 65535."
                raise ValueError(msg)
            if not (0 <= record.record_number <= 9999):
                msg = "Record number must be between 0 and 9999."
                raise ValueError(msg)
            if not (0 <= len(record.data) <= 0xFFFF):
                msg = "Record data length must be between 0 and 65535 bytes."
                raise ValueError(msg)

        if not self.file_records:
            msg = "At least one file record is required."
            raise ValueError(msg)

        # Each record is a 7-byte header plus its data, padded up to an even length.
        byte_count = sum(
            SUB_REQUEST_STRUCT.size + len(record.data) + (len(record.data) % 2) for record in self.file_records
        )
        if byte_count > MAX_WRITE_FILE_RECORD_BYTE_COUNT:
            msg = (
                f"Write File Record request byte count {byte_count} exceeds the "
                f"maximum of {MAX_WRITE_FILE_RECORD_BYTE_COUNT}."
            )
            raise ValueError(msg)

    @classmethod
    def _encode(cls, file_records: list[FileRecord]) -> bytes:
        """Encode the PDU into bytes.

        Returns:
            Encoded bytes of the PDU.

        """
        records_bytes = b""
        for record in file_records:
            record_data = record.data
            if len(record_data) % 2 != 0:
                msg = "Record data length cannot be odd; each register is 2 bytes."
                raise ValueError(msg)

            records_bytes += SUB_REQUEST_STRUCT.pack(
                FILE_RECORD_REFERENCE_TYPE,
                record.file_number,
                record.record_number,
                len(record_data) // 2,  # length in registers
            )
            records_bytes += record_data

        byte_count = len(records_bytes)
        return struct.pack(">BB", cls.function_code, byte_count) + records_bytes

    @classmethod
    def _decode(cls, response: bytes) -> list[FileRecord]:
        """Decode the response PDU.

        Args:
            response: Bytes to decode.

        Returns:
            List of FileRecord instances as echoed by the server.

        Raises:
            InvalidResponseError: If the response is invalid.

        """
        try:
            function_code, byte_count = struct.unpack_from(">BB", response, 0)
        except struct.error as e:
            msg = "Expected response to start with function code and byte count"
            raise InvalidResponseError(msg, response_bytes=response) from e

        if function_code != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {function_code:#04x}"
            raise InvalidResponseError(msg, response_bytes=response)

        if len(response) - 2 != byte_count:
            msg = f"Response length {len(response)} is not equal to expected {2 + byte_count}"
            raise InvalidResponseError(msg, response_bytes=response)

        records: list[FileRecord] = []
        offset = 2
        end_offset = 2 + byte_count

        while offset < end_offset:
            try:
                reference_type, file_number, record_number, record_length = SUB_REQUEST_STRUCT.unpack_from(
                    response, offset
                )
            except struct.error as e:
                msg = "Failed to unpack file record header"
                raise InvalidResponseError(msg, response_bytes=response) from e

            if reference_type != FILE_RECORD_REFERENCE_TYPE:
                msg = (
                    f"Invalid reference type: expected {FILE_RECORD_REFERENCE_TYPE:#04x}, "
                    f"received {reference_type:#04x}"
                )
                raise InvalidResponseError(msg, response_bytes=response)

            data_start = offset + SUB_REQUEST_STRUCT.size
            data_end = data_start + record_length * 2  # each register is 2 bytes

            if data_end > len(response):
                msg = "Not enough data for the specified record length"
                raise InvalidResponseError(msg, response_bytes=response)

            record_data = response[data_start:data_end]
            records.append(FileRecord(file_number, record_number, record_data))

            offset = data_end

        return records

    def encode_request(self) -> bytes:
        """Encode the request PDU.

        Returns:
            Encoded bytes of the PDU.

        """
        return WriteFileRecordPDU._encode(self.file_records)

    def decode_response(self, response: bytes) -> list[FileRecord]:
        """Decode the response PDU.

        Args:
            response: Bytes to decode.

        Returns:
            List of FileRecord instances as echoed by the server.

        Raises:
            InvalidResponseError: If the response is invalid.

        """
        return WriteFileRecordPDU._decode(response)

    def encode_response(self, value: list[FileRecord]) -> bytes:
        """Encode the response PDU.

        Args:
            value: List of FileRecord instances to encode.

        Returns:
            Encoded bytes of the PDU.

        """
        return WriteFileRecordPDU._encode(value)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode the request PDU.

        Args:
            request: Bytes to decode.

        Returns:
            List of FileRecord instances as requested.

        Raises:
            InvalidRequestError: If the request is invalid.

        """
        try:
            function_code, byte_count = struct.unpack_from(">BB", request, 0)
        except struct.error as e:
            msg = "Expected request to start with function code and byte count"
            raise InvalidRequestError(msg, request_bytes=request) from e

        if function_code != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {function_code:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        if len(request) - 2 != byte_count:
            msg = f"Request length {len(request)} is not equal to expected {2 + byte_count}"
            raise InvalidRequestError(msg, request_bytes=request)

        records: list[FileRecord] = []
        offset = 2
        end_offset = 2 + byte_count

        while offset < end_offset:
            try:
                reference_type, file_number, record_number, record_length = SUB_REQUEST_STRUCT.unpack_from(
                    request, offset
                )
            except struct.error as e:
                msg = "Failed to unpack file record header"
                raise InvalidRequestError(msg, request_bytes=request) from e

            if reference_type != FILE_RECORD_REFERENCE_TYPE:
                msg = (
                    f"Invalid reference type: expected {FILE_RECORD_REFERENCE_TYPE:#04x}, "
                    f"received {reference_type:#04x}"
                )
                raise InvalidRequestError(msg, request_bytes=request)

            data_start = offset + SUB_REQUEST_STRUCT.size
            data_end = data_start + record_length * 2

            if data_end > len(request):
                msg = "Not enough data for the specified record length"
                raise InvalidRequestError(msg, request_bytes=request)

            record_data = request[data_start:data_end]
            records.append(FileRecord(file_number, record_number, record_data))
            offset = data_end

        try:
            return cls(records)
        except ValueError as e:
            raise InvalidRequestError(str(e), request_bytes=request) from e

    @classmethod
    def get_expected_request_data_length(cls, data: bytes) -> int:
        """Get the expected number of bytes for the data part of the request PDU."""
        return 1 + data[0]
