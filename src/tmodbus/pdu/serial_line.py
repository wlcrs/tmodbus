"""PDU's that are specific to serial line communication."""

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from tmodbus.const import FunctionCode
from tmodbus.exceptions import FunctionCodeError, InvalidRequestError, InvalidResponseError

from .base import BasePDU, BaseSubFunctionPDU


class DiagnosticSubFunction(IntEnum):
    """Sub-function codes for Diagnostics (Function Code 0x08)."""

    RETURN_QUERY_DATA = 0x0000
    RESTART_COMMUNICATIONS_OPTION = 0x0001
    RETURN_DIAGNOSTIC_REGISTER = 0x0002
    CHANGE_ASCII_INPUT_DELIMITER = 0x0003
    FORCE_LISTEN_ONLY_MODE = 0x0004
    CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER = 0x000A
    RETURN_BUS_MESSAGE_COUNT = 0x000B
    RETURN_BUS_COMMUNICATION_ERROR_COUNT = 0x000C
    RETURN_BUS_EXCEPTION_ERROR_COUNT = 0x000D
    RETURN_SERVER_MESSAGE_COUNT = 0x000E
    RETURN_SERVER_NO_RESPONSE_COUNT = 0x000F
    RETURN_SERVER_NAK_COUNT = 0x0010
    RETURN_SERVER_BUSY_COUNT = 0x0011
    RETURN_BUS_CHARACTER_OVERRUN_COUNT = 0x0012
    CLEAR_OVERRUN_COUNTER_AND_FLAG = 0x0014


class BaseDiagnosticsSubFunctionPDU[RT](BaseSubFunctionPDU[RT]):
    """Base class for diagnostic sub-function PDUs (Function Code 0x08)."""

    function_code = FunctionCode.DIAGNOSTICS
    sub_function_code_length = 2


class DiagnosticsQueryDataPDU(BaseDiagnosticsSubFunctionPDU[bytes]):
    """Diagnostics sub-function 0x0000: Return Query Data."""

    sub_function_code = DiagnosticSubFunction.RETURN_QUERY_DATA
    rtu_request_data_length = 4  # sub-function (2) + query data (2)
    rtu_response_data_length = 4

    def __init__(self, data: bytes = b"\x00\x00") -> None:
        """Initialize DiagnosticsQueryDataPDU.

        Args:
            data: Data bytes to loop back (must be an even number of bytes).
                Payloads longer than 2 bytes cannot be framed over RTU.

        """
        if len(data) % 2 != 0:
            msg = "Diagnostics query data must be an even number of bytes"
            raise ValueError(msg)
        self.data = data

    def encode_request(self) -> bytes:
        """Encode request PDU."""
        return struct.pack(">BH", self.function_code, self.sub_function_code) + self.data

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode request PDU."""
        if len(request) < 3:
            msg = f"Request length {len(request)} is too short"
            raise InvalidRequestError(msg, request_bytes=request)

        fc, sub_func = struct.unpack_from(">BH", request, 0)
        if fc != cls.function_code or sub_func != cls.sub_function_code:
            msg = f"Invalid function/sub-function: expected {cls.function_code:#04x}/{cls.sub_function_code:#06x}"
            raise InvalidRequestError(msg, request_bytes=request)

        data = request[3:]
        if len(data) % 2 != 0:
            msg = "Diagnostics query data must be an even number of bytes"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls(data=data)

    def encode_response(self, value: bytes) -> bytes:
        """Encode response PDU."""
        # Return Query Data must echo the request data exactly.
        if len(value) != len(self.data):
            msg = f"Diagnostics query data response length {len(value)} does not match request length {len(self.data)}"
            raise ValueError(msg)
        return struct.pack(">BH", self.function_code, self.sub_function_code) + value

    def decode_response(self, response: bytes) -> bytes:
        """Decode response PDU."""
        if len(response) < 3:
            msg = f"Response length {len(response)} is too short"
            raise InvalidResponseError(msg, response_bytes=response)

        fc, sub_func = struct.unpack_from(">BH", response, 0)
        if fc != self.function_code or sub_func != self.sub_function_code:
            msg = f"Invalid function/sub-function: expected {self.function_code:#04x}/{self.sub_function_code:#06x}"
            raise FunctionCodeError(msg, response_bytes=response)

        data = response[3:]
        if len(data) % 2 != 0:
            msg = "Diagnostics query data must be an even number of bytes"
            raise InvalidResponseError(msg, response_bytes=response)

        return data


class DiagnosticsRestartCommunicationsOptionPDU(BaseDiagnosticsSubFunctionPDU[bool]):
    """Diagnostics sub-function 0x0001: Restart Communications Option."""

    sub_function_code = DiagnosticSubFunction.RESTART_COMMUNICATIONS_OPTION
    rtu_request_data_length = 4
    rtu_response_data_length = 4

    def __init__(self, clear_event_log: bool = False) -> None:  # noqa: FBT001, FBT002
        """Initialize DiagnosticsRestartCommunicationsOptionPDU.

        Args:
            clear_event_log: Whether to clear the communications event log.

        """
        self.clear_event_log = clear_event_log

    def get_broadcast_response(self) -> bool:
        """Return dummy response for a broadcast request."""
        return self.clear_event_log

    def encode_request(self) -> bytes:
        """Encode request PDU."""
        data_val = 0xFF00 if self.clear_event_log else 0x0000
        return struct.pack(">BHH", self.function_code, self.sub_function_code, data_val)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode request PDU."""
        if len(request) != 5:
            msg = f"Request length {len(request)} does not match expected 5"
            raise InvalidRequestError(msg, request_bytes=request)

        fc, sub_func, data_val = struct.unpack(">BHH", request)
        if fc != cls.function_code or sub_func != cls.sub_function_code:
            msg = f"Invalid function/sub-function: expected {cls.function_code:#04x}/{cls.sub_function_code:#06x}"
            raise InvalidRequestError(msg, request_bytes=request)

        if data_val not in (0x0000, 0xFF00):
            msg = f"Invalid restart option data: {data_val:#06x}, expected 0x0000 or 0xFF00"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls(clear_event_log=(data_val == 0xFF00))

    def encode_response(self, value: bool) -> bytes:  # noqa: FBT001
        """Encode response PDU."""
        data_val = 0xFF00 if value else 0x0000
        return struct.pack(">BHH", self.function_code, self.sub_function_code, data_val)

    def decode_response(self, response: bytes) -> bool:
        """Decode response PDU."""
        if len(response) != 5:
            msg = f"Response length {len(response)} does not match expected 5"
            raise InvalidResponseError(msg, response_bytes=response)

        fc, sub_func, data_val = struct.unpack(">BHH", response)
        if fc != self.function_code or sub_func != self.sub_function_code:
            msg = f"Invalid function/sub-function: expected {self.function_code:#04x}/{self.sub_function_code:#06x}"
            raise FunctionCodeError(msg, response_bytes=response)

        if data_val not in (0x0000, 0xFF00):
            msg = f"Invalid restart option response data: {data_val:#06x}"
            raise InvalidResponseError(msg, response_bytes=response)

        return bool(data_val == 0xFF00)


class DiagnosticsDiagnosticRegisterPDU(BaseDiagnosticsSubFunctionPDU[int]):
    """Diagnostics sub-function 0x0002: Return Diagnostic Register."""

    sub_function_code = DiagnosticSubFunction.RETURN_DIAGNOSTIC_REGISTER
    rtu_request_data_length = 4
    rtu_response_data_length = 4

    def __init__(self) -> None:
        """Initialize DiagnosticsDiagnosticRegisterPDU."""

    def encode_request(self) -> bytes:
        """Encode request PDU."""
        return struct.pack(">BHH", self.function_code, self.sub_function_code, 0x0000)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode request PDU."""
        if len(request) != 5:
            msg = f"Request length {len(request)} does not match expected 5"
            raise InvalidRequestError(msg, request_bytes=request)

        fc, sub_func, _data_val = struct.unpack(">BHH", request)
        if fc != cls.function_code or sub_func != cls.sub_function_code:
            msg = f"Invalid function/sub-function: expected {cls.function_code:#04x}/{cls.sub_function_code:#06x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls()

    def encode_response(self, value: int) -> bytes:
        """Encode response PDU."""
        if not (0 <= value <= 0xFFFF):
            msg = f"Diagnostic register value {value} out of range (0-65535)"
            raise ValueError(msg)
        return struct.pack(">BHH", self.function_code, self.sub_function_code, value)

    def decode_response(self, response: bytes) -> int:
        """Decode response PDU."""
        if len(response) != 5:
            msg = f"Response length {len(response)} does not match expected 5"
            raise InvalidResponseError(msg, response_bytes=response)

        fc, sub_func, reg_val = struct.unpack(">BHH", response)
        if fc != self.function_code or sub_func != self.sub_function_code:
            msg = f"Invalid function/sub-function: expected {self.function_code:#04x}/{self.sub_function_code:#06x}"
            raise FunctionCodeError(msg, response_bytes=response)

        return int(reg_val)


class DiagnosticsChangeAsciiInputDelimiterPDU(BaseDiagnosticsSubFunctionPDU[int]):
    """Diagnostics sub-function 0x0003: Change ASCII Input Delimiter."""

    sub_function_code = DiagnosticSubFunction.CHANGE_ASCII_INPUT_DELIMITER
    rtu_request_data_length = 4
    rtu_response_data_length = 4

    def __init__(self, delimiter: int = 0x0A) -> None:
        """Initialize DiagnosticsChangeAsciiInputDelimiterPDU.

        Args:
            delimiter: ASCII delimiter character code (0-255).

        """
        if not (0 <= delimiter <= 0xFF):
            msg = f"Delimiter {delimiter} out of range (0-255)"
            raise ValueError(msg)
        self.delimiter = delimiter

    def encode_request(self) -> bytes:
        """Encode request PDU."""
        return struct.pack(">BHBB", self.function_code, self.sub_function_code, self.delimiter, 0x00)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode request PDU."""
        if len(request) != 5:
            msg = f"Request length {len(request)} does not match expected 5"
            raise InvalidRequestError(msg, request_bytes=request)

        fc, sub_func, delim, _pad = struct.unpack(">BHBB", request)
        if fc != cls.function_code or sub_func != cls.sub_function_code:
            msg = f"Invalid function/sub-function: expected {cls.function_code:#04x}/{cls.sub_function_code:#06x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls(delimiter=delim)

    def encode_response(self, value: int) -> bytes:
        """Encode response PDU."""
        if not (0 <= value <= 0xFF):
            msg = f"Delimiter {value} out of range (0-255)"
            raise ValueError(msg)
        return struct.pack(">BHBB", self.function_code, self.sub_function_code, value, 0x00)

    def decode_response(self, response: bytes) -> int:
        """Decode response PDU."""
        if len(response) != 5:
            msg = f"Response length {len(response)} does not match expected 5"
            raise InvalidResponseError(msg, response_bytes=response)

        _fc, _sub_func, delim, _pad = struct.unpack(">BHBB", response)
        if _fc != self.function_code or _sub_func != self.sub_function_code:
            msg = f"Invalid function/sub-function: expected {self.function_code:#04x}/{self.sub_function_code:#06x}"
            raise FunctionCodeError(msg, response_bytes=response)

        return int(delim)


class DiagnosticsForceListenOnlyModePDU(BaseDiagnosticsSubFunctionPDU[None]):
    """Diagnostics sub-function 0x0004: Force Listen Only Mode."""

    sub_function_code = DiagnosticSubFunction.FORCE_LISTEN_ONLY_MODE
    rtu_request_data_length = 4
    rtu_response_data_length = 4
    expects_response = False

    def get_broadcast_response(self) -> None:
        """Get response for Force Listen Only Mode (no response)."""
        return

    def __init__(self) -> None:
        """Initialize DiagnosticsForceListenOnlyModePDU."""

    def encode_request(self) -> bytes:
        """Encode request PDU."""
        return struct.pack(">BHH", self.function_code, self.sub_function_code, 0x0000)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode request PDU."""
        if len(request) != 5:
            msg = f"Request length {len(request)} does not match expected 5"
            raise InvalidRequestError(msg, request_bytes=request)

        fc, sub_func, _data_val = struct.unpack(">BHH", request)
        if fc != cls.function_code or sub_func != cls.sub_function_code:
            msg = f"Invalid function/sub-function: expected {cls.function_code:#04x}/{cls.sub_function_code:#06x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls()

    def encode_response(self, _value: None = None) -> bytes:
        """Encode response PDU."""
        return b""

    def decode_response(self, response: bytes) -> None:
        """Decode response PDU."""
        msg = "No response expected"
        raise InvalidResponseError(msg, response_bytes=response)


class DiagnosticsClearCountersAndRegisterPDU(BaseDiagnosticsSubFunctionPDU[None]):
    """Diagnostics sub-function 0x000A: Clear Counters and Diagnostic Register."""

    sub_function_code = DiagnosticSubFunction.CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER
    rtu_request_data_length = 4
    rtu_response_data_length = 4

    def __init__(self) -> None:
        """Initialize DiagnosticsClearCountersAndRegisterPDU."""

    def encode_request(self) -> bytes:
        """Encode request PDU."""
        return struct.pack(">BHH", self.function_code, self.sub_function_code, 0x0000)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode request PDU."""
        if len(request) != 5:
            msg = f"Request length {len(request)} does not match expected 5"
            raise InvalidRequestError(msg, request_bytes=request)

        fc, sub_func, _data_val = struct.unpack(">BHH", request)
        if fc != cls.function_code or sub_func != cls.sub_function_code:
            msg = f"Invalid function/sub-function: expected {cls.function_code:#04x}/{cls.sub_function_code:#06x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls()

    def encode_response(self, _value: None = None) -> bytes:
        """Encode response PDU."""
        return struct.pack(">BHH", self.function_code, self.sub_function_code, 0x0000)

    def decode_response(self, response: bytes) -> None:
        """Decode response PDU."""
        if len(response) != 5:
            msg = f"Response length {len(response)} does not match expected 5"
            raise InvalidResponseError(msg, response_bytes=response)

        fc, sub_func, _data_val = struct.unpack(">BHH", response)
        if fc != self.function_code or sub_func != self.sub_function_code:
            msg = f"Invalid function/sub-function: expected {self.function_code:#04x}/{self.sub_function_code:#06x}"
            raise FunctionCodeError(msg, response_bytes=response)


class BaseDiagnosticsCounterPDU(BaseDiagnosticsSubFunctionPDU[int]):
    """Base class for Diagnostics counter sub-function PDUs."""

    rtu_request_data_length = 4
    rtu_response_data_length = 4

    def __init__(self) -> None:
        """Initialize counter PDU."""

    def encode_request(self) -> bytes:
        """Encode request PDU."""
        return struct.pack(">BHH", self.function_code, self.sub_function_code, 0x0000)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode request PDU."""
        if len(request) != 5:
            msg = f"Request length {len(request)} does not match expected 5"
            raise InvalidRequestError(msg, request_bytes=request)

        fc, sub_func, _data_val = struct.unpack(">BHH", request)
        if fc != cls.function_code or sub_func != cls.sub_function_code:
            msg = f"Invalid function/sub-function: expected {cls.function_code:#04x}/{cls.sub_function_code:#06x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls()

    def encode_response(self, value: int) -> bytes:
        """Encode response PDU."""
        if not (0 <= value <= 0xFFFF):
            msg = f"Counter value {value} out of range (0-65535)"
            raise ValueError(msg)
        return struct.pack(">BHH", self.function_code, self.sub_function_code, value)

    def decode_response(self, response: bytes) -> int:
        """Decode response PDU."""
        if len(response) != 5:
            msg = f"Response length {len(response)} does not match expected 5"
            raise InvalidResponseError(msg, response_bytes=response)

        fc, sub_func, count = struct.unpack(">BHH", response)
        if fc != self.function_code or sub_func != self.sub_function_code:
            msg = f"Invalid function/sub-function: expected {self.function_code:#04x}/{self.sub_function_code:#06x}"
            raise FunctionCodeError(msg, response_bytes=response)

        return int(count)


class DiagnosticsBusMessageCountPDU(BaseDiagnosticsCounterPDU):
    """Diagnostics sub-function 0x000B: Return Bus Message Count."""

    sub_function_code = DiagnosticSubFunction.RETURN_BUS_MESSAGE_COUNT


class DiagnosticsBusCommunicationErrorCountPDU(BaseDiagnosticsCounterPDU):
    """Diagnostics sub-function 0x000C: Return Bus Communication Error Count."""

    sub_function_code = DiagnosticSubFunction.RETURN_BUS_COMMUNICATION_ERROR_COUNT


class DiagnosticsBusExceptionErrorCountPDU(BaseDiagnosticsCounterPDU):
    """Diagnostics sub-function 0x000D: Return Bus Exception Error Count."""

    sub_function_code = DiagnosticSubFunction.RETURN_BUS_EXCEPTION_ERROR_COUNT


class DiagnosticsServerMessageCountPDU(BaseDiagnosticsCounterPDU):
    """Diagnostics sub-function 0x000E: Return Server Message Count."""

    sub_function_code = DiagnosticSubFunction.RETURN_SERVER_MESSAGE_COUNT


class DiagnosticsServerNoResponseCountPDU(BaseDiagnosticsCounterPDU):
    """Diagnostics sub-function 0x000F: Return Server No Response Count."""

    sub_function_code = DiagnosticSubFunction.RETURN_SERVER_NO_RESPONSE_COUNT


class DiagnosticsServerNakCountPDU(BaseDiagnosticsCounterPDU):
    """Diagnostics sub-function 0x0010: Return Server NAK Count."""

    sub_function_code = DiagnosticSubFunction.RETURN_SERVER_NAK_COUNT


class DiagnosticsServerBusyCountPDU(BaseDiagnosticsCounterPDU):
    """Diagnostics sub-function 0x0011: Return Server Busy Count."""

    sub_function_code = DiagnosticSubFunction.RETURN_SERVER_BUSY_COUNT


class DiagnosticsBusCharacterOverrunCountPDU(BaseDiagnosticsCounterPDU):
    """Diagnostics sub-function 0x0012: Return Bus Character Overrun Count."""

    sub_function_code = DiagnosticSubFunction.RETURN_BUS_CHARACTER_OVERRUN_COUNT


class DiagnosticsClearOverrunCounterAndFlagPDU(BaseDiagnosticsSubFunctionPDU[None]):
    """Diagnostics sub-function 0x0014: Clear Overrun Counter and Flag."""

    sub_function_code = DiagnosticSubFunction.CLEAR_OVERRUN_COUNTER_AND_FLAG
    rtu_request_data_length = 4
    rtu_response_data_length = 4

    def __init__(self) -> None:
        """Initialize DiagnosticsClearOverrunCounterAndFlagPDU."""

    def encode_request(self) -> bytes:
        """Encode request PDU."""
        return struct.pack(">BHH", self.function_code, self.sub_function_code, 0x0000)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode request PDU."""
        if len(request) != 5:
            msg = f"Request length {len(request)} does not match expected 5"
            raise InvalidRequestError(msg, request_bytes=request)

        fc, sub_func, _data_val = struct.unpack(">BHH", request)
        if fc != cls.function_code or sub_func != cls.sub_function_code:
            msg = f"Invalid function/sub-function: expected {cls.function_code:#04x}/{cls.sub_function_code:#06x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls()

    def encode_response(self, _value: None = None) -> bytes:
        """Encode response PDU."""
        return struct.pack(">BHH", self.function_code, self.sub_function_code, 0x0000)

    def decode_response(self, response: bytes) -> None:
        """Decode response PDU."""
        if len(response) != 5:
            msg = f"Response length {len(response)} does not match expected 5"
            raise InvalidResponseError(msg, response_bytes=response)

        fc, sub_func, _data_val = struct.unpack(">BHH", response)
        if fc != self.function_code or sub_func != self.sub_function_code:
            msg = f"Invalid function/sub-function: expected {self.function_code:#04x}/{self.sub_function_code:#06x}"
            raise FunctionCodeError(msg, response_bytes=response)


@dataclass(frozen=True)
class CommEventCounterResponse:
    """Response data structure for Get Comm Event Counter (FC0B)."""

    status: int
    event_count: int


class GetCommEventCounterPDU(BasePDU[CommEventCounterResponse]):
    """PDU for Get Comm Event Counter (function code 0x0B)."""

    function_code = FunctionCode.GET_COM_EVENT_COUNTER
    rtu_request_data_length = 0
    rtu_response_data_length = 4

    def __init__(self) -> None:
        """Initialize GetCommEventCounterPDU."""

    def encode_request(self) -> bytes:
        """Encode the PDU into bytes."""
        return bytes([self.function_code])

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode bytes into a GetCommEventCounterPDU instance."""
        if len(request) != 1:
            msg = f"Expected request with only function code, got {len(request)} bytes"
            raise InvalidRequestError(msg, request_bytes=request)

        if request[0] != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {request[0]:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls()

    def encode_response(self, value: CommEventCounterResponse) -> bytes:
        """Encode the response PDU."""
        if value.status not in (0x0000, 0xFFFF):
            msg = f"Status {value.status:#06x} invalid, expected 0x0000 or 0xFFFF"
            raise ValueError(msg)
        if not (0 <= value.event_count <= 0xFFFF):
            msg = f"Event count {value.event_count} out of range (0-65535)"
            raise ValueError(msg)
        return struct.pack(">BHH", self.function_code, value.status, value.event_count)

    def decode_response(self, response: bytes) -> CommEventCounterResponse:
        """Decode the response PDU."""
        if len(response) != 5:
            msg = f"Response length {len(response)} does not match expected 5"
            raise InvalidResponseError(msg, response_bytes=response)

        function_code, status, event_count = struct.unpack(">BHH", response)
        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:#04x}, received {function_code:#04x}"
            raise FunctionCodeError(msg, response_bytes=response)

        return CommEventCounterResponse(status=status, event_count=event_count)


# Alias matching const FunctionCode naming convention
GetComEventCounterPDU = GetCommEventCounterPDU


MAX_COMM_EVENT_LOG_EVENTS = 64


@dataclass(frozen=True)
class CommEventLogResponse:
    """Response data structure for Get Comm Event Log (FC0C)."""

    status: int
    event_count: int
    message_count: int
    events: bytes


class GetCommEventLogPDU(BasePDU[CommEventLogResponse]):
    """PDU for Get Comm Event Log (function code 0x0C)."""

    function_code = FunctionCode.GET_COM_EVENT_LOG
    rtu_request_data_length = 0

    def __init__(self) -> None:
        """Initialize GetCommEventLogPDU."""

    def encode_request(self) -> bytes:
        """Encode the PDU into bytes."""
        return bytes([self.function_code])

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode bytes into a GetCommEventLogPDU instance."""
        if len(request) != 1:
            msg = f"Expected request with only function code, got {len(request)} bytes"
            raise InvalidRequestError(msg, request_bytes=request)

        if request[0] != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {request[0]:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls()

    def encode_response(self, value: CommEventLogResponse) -> bytes:
        """Encode the response PDU."""
        # The specification caps the event log at 64 single-byte events.
        if len(value.events) > MAX_COMM_EVENT_LOG_EVENTS:
            msg = f"Comm event log length {len(value.events)} exceeds the maximum of {MAX_COMM_EVENT_LOG_EVENTS}."
            raise ValueError(msg)
        byte_count = 6 + len(value.events)
        return (
            struct.pack(">BBHHH", self.function_code, byte_count, value.status, value.event_count, value.message_count)
            + value.events
        )

    def decode_response(self, response: bytes) -> CommEventLogResponse:
        """Decode the response PDU."""
        if len(response) < 8:
            msg = f"Response length {len(response)} is too short, expected at least 8 bytes"
            raise InvalidResponseError(msg, response_bytes=response)

        function_code, byte_count, status, event_count, message_count = struct.unpack_from(">BBHHH", response, 0)
        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:#04x}, received {function_code:#04x}"
            raise FunctionCodeError(msg, response_bytes=response)

        if len(response) != 2 + byte_count:
            msg = f"Response length {len(response)} does not match expected {2 + byte_count}"
            raise InvalidResponseError(msg, response_bytes=response)

        events = response[8:]
        return CommEventLogResponse(
            status=status,
            event_count=event_count,
            message_count=message_count,
            events=events,
        )


# Alias matching const FunctionCode naming convention
GetComEventLogPDU = GetCommEventLogPDU


@dataclass(frozen=True)
class ServerIdResponse:
    """Response data structure for Report Server ID."""

    server_id: bytes
    run_indicator_status: bool
    additional_data: bytes


ID_ON = 0xFF
ID_OFF = 0x00


class ReportServerIdPDU(BasePDU[ServerIdResponse]):
    """PDU for Report Server ID (function code 0x11)."""

    function_code = 0x11
    rtu_request_data_length = 0  # no data

    def __init__(self) -> None:
        """Initialize ReportServerIdPDU."""

    def encode_request(self) -> bytes:
        """Encode the PDU into bytes.

        Returns:
            Encoded bytes of the PDU.

        """
        return bytes([self.function_code])

    def decode_response(self, response: bytes) -> ServerIdResponse:
        """Decode the response PDU.

        Args:
            response: Bytes to decode.

        Returns:
            Instance of ServerIdResponse.

        Raises:
            InvalidResponseError: If the response is invalid.
            FunctionCodeError: If function code is incorrect.

        Note:
            The specification does not delimit the server ID: this method treats the first
            0x00/0xFF byte after the byte count as the run indicator status. A server ID that
            itself contains 0x00 or 0xFF is therefore mis-split into server_id/run
            indicator/additional_data.

        """
        # response format: function code (1 byte) + byte count (1 byte) + server ID + status (1 byte)

        # note: the protocol doesn't specify where the server ID ends and where the additional data starts
        # we can find the status byte by looking for the first occurrence of 0xFF or 0x00 after the byte count

        try:
            function_code, byte_count = struct.unpack_from(">BB", response, 0)
        except struct.error as e:
            msg = "Expected response to start with function code and byte count"
            raise InvalidResponseError(msg, response_bytes=response) from e

        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:#04x}, received {function_code:#04x}"
            raise FunctionCodeError(msg, response_bytes=response)

        if len(response) != 2 + byte_count:
            msg = f"Response length {len(response)} does not match expected {2 + byte_count}"
            raise InvalidResponseError(msg, response_bytes=response)

        # we can the data after the byte count for the status indicator byte to know
        # where the server_id ends and where the additional data starts

        for idx in range(2, 2 + byte_count):
            if response[idx] in (ID_ON, ID_OFF):
                server_id = response[2:idx]
                run_indicator_status = response[idx] == ID_ON
                additional_data = response[idx + 1 : 2 + byte_count]
                break
        else:
            msg = "Run indicator status byte not found in response"
            raise InvalidResponseError(msg, response_bytes=response)

        return ServerIdResponse(
            server_id=server_id,
            run_indicator_status=run_indicator_status,
            additional_data=additional_data,
        )

    @classmethod
    def decode_request(cls, data: bytes) -> Self:
        """Decode bytes into a PDU instance.

        Args:
            data: Bytes to decode.

        Returns:
            Instance of ReportServerIdPDU.

        Raises:
            InvalidRequestError: If the data is invalid.

        """
        if len(data) != 1:
            msg = "Expected request with only function code"
            raise InvalidRequestError(msg)

        if data[0] != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {data[0]:#04x}"
            raise InvalidRequestError(msg)
        return cls()

    def encode_response(self, value: ServerIdResponse) -> bytes:
        """Encode the response PDU.

        Args:
            value: Instance of ServerIdResponse to encode.

        Returns:
            Encoded bytes of the response PDU.

        Raises:
            ValueError: If the byte count is out of range, or the server ID contains 0x00 or 0xFF.

        """
        # decode_response locates the run indicator status as the first 0x00/0xFF byte after
        # the byte count, so those values inside the server ID would corrupt the round-trip.
        if ID_ON in value.server_id or ID_OFF in value.server_id:
            msg = "Server ID must not contain 0x00 or 0xFF bytes"
            raise ValueError(msg)
        byte_count = len(value.server_id) + 1 + len(value.additional_data)  # +1 for run indicator status
        if byte_count > 0xFF:
            msg = f"Server ID response byte count {byte_count} exceeds the maximum of 255."
            raise ValueError(msg)
        run_indicator_status = ID_ON if value.run_indicator_status else ID_OFF
        return bytes([self.function_code, byte_count, *value.server_id, run_indicator_status, *value.additional_data])
