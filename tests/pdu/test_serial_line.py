"""Tests for serial line PDUs."""

import struct

import pytest
from tmodbus.exceptions import FunctionCodeError, InvalidRequestError, InvalidResponseError
from tmodbus.pdu.serial_line import (
    ID_OFF,
    ID_ON,
    CommEventCounterResponse,
    CommEventLogResponse,
    DiagnosticsBusCharacterOverrunCountPDU,
    DiagnosticsBusCommunicationErrorCountPDU,
    DiagnosticsBusExceptionErrorCountPDU,
    DiagnosticsBusMessageCountPDU,
    DiagnosticsChangeAsciiInputDelimiterPDU,
    DiagnosticsClearCountersAndRegisterPDU,
    DiagnosticsClearOverrunCounterAndFlagPDU,
    DiagnosticsDiagnosticRegisterPDU,
    DiagnosticsForceListenOnlyModePDU,
    DiagnosticsQueryDataPDU,
    DiagnosticsRestartCommunicationsOptionPDU,
    DiagnosticsServerBusyCountPDU,
    DiagnosticsServerMessageCountPDU,
    DiagnosticsServerNakCountPDU,
    DiagnosticsServerNoResponseCountPDU,
    GetCommEventCounterPDU,
    GetCommEventLogPDU,
    ReportServerIdPDU,
    ServerIdResponse,
)


def make_response(
    function_code: int, server_id: bytes, run_indicator_status: int, additional_data: bytes = b""
) -> bytes:
    """Construct a valid ReportServerIdPDU response byte string.

    Args:
        function_code: The Modbus function code (int)
        server_id: The server ID as bytes
        run_indicator_status: Status byte (ID_ON or ID_OFF)
        additional_data: Any additional data as bytes
    Returns:
        Bytes representing a valid response for ReportServerIdPDU

    """
    byte_count = len(server_id) + 1 + len(additional_data)
    return bytes([function_code, byte_count]) + server_id + bytes([run_indicator_status]) + additional_data


def test_encode_request() -> None:
    """Test that ReportServerIdPDU.encode_request returns the correct function code byte."""
    pdu = ReportServerIdPDU()
    assert pdu.encode_request() == bytes([pdu.function_code])


def test_decode_response_valid() -> None:
    """Test decode_response parses valid responses with both ON and OFF status and additional data."""
    pdu = ReportServerIdPDU()
    server_id = b"abc"
    additional = b"xyz"
    response = make_response(pdu.function_code, server_id, ID_ON, additional)
    result = pdu.decode_response(response)
    assert result.server_id == server_id
    assert result.run_indicator_status is True
    assert result.additional_data == additional

    response = make_response(pdu.function_code, server_id, ID_OFF, b"")
    result = pdu.decode_response(response)
    assert result.server_id == server_id
    assert result.run_indicator_status is False
    assert result.additional_data == b""


def test_decode_response_invalid_function_code() -> None:
    """Test decode_response raises InvalidResponseError if the function code is not correct."""
    pdu = ReportServerIdPDU()
    response = make_response(0x12, b"abc", ID_ON, b"")
    with pytest.raises(InvalidResponseError, match="Invalid function code"):
        pdu.decode_response(response)


def test_decode_response_trailing_bytes() -> None:
    """Trailing bytes beyond the declared byte count are rejected."""
    pdu = ReportServerIdPDU()
    response = make_response(pdu.function_code, b"abc", ID_ON, b"xyz") + b"\x00\x00"
    with pytest.raises(InvalidResponseError, match="Response length"):
        pdu.decode_response(response)


def test_decode_response_invalid_length() -> None:
    """Test decode_response raises InvalidResponseError if the response is too short for the byte count."""
    pdu = ReportServerIdPDU()
    # byte_count too large
    response = bytes([pdu.function_code, 10]) + b"a" * 3
    with pytest.raises(InvalidResponseError, match="Response length"):
        pdu.decode_response(response)


def test_decode_response_missing_status() -> None:
    """Test decode_response raises InvalidResponseError if no status byte (ID_ON/ID_OFF) is present."""
    pdu = ReportServerIdPDU()
    # No status byte (neither ID_ON nor ID_OFF)
    response = bytes([pdu.function_code, 3]) + b"abc"
    with pytest.raises(InvalidResponseError, match="Run indicator status byte not found"):
        pdu.decode_response(response)


def test_decode_response_struct_error() -> None:
    """Test decode_response raises InvalidResponseError on struct.error (malformed response).

    Covers the struct.error branch for unpacking.
    """
    pdu = ReportServerIdPDU()
    # Too short to unpack two bytes
    response = b"\x11"
    with pytest.raises(
        InvalidResponseError, match="Expected response to start with function code and byte count"
    ) as excinfo:
        pdu.decode_response(response)
    # Optionally check that the cause is struct.error
    assert isinstance(excinfo.value.__cause__, struct.error)


def test_decode_request_valid() -> None:
    """Test decode_request accepts a valid single-byte request and returns the same PDU instance."""
    data = bytes([0x11])
    assert ReportServerIdPDU.decode_request(data)


def test_decode_request_invalid_length() -> None:
    """Test decode_request raises InvalidRequestError if the request is longer than one byte."""
    data = bytes([0x11, 0x01])
    with pytest.raises(InvalidRequestError, match="Expected request with only function code"):
        ReportServerIdPDU.decode_request(data)


def test_decode_request_invalid_function_code() -> None:
    """Test decode_request raises InvalidRequestError if the function code is not correct."""
    data = bytes([0x12])
    with pytest.raises(InvalidRequestError, match="Invalid function code"):
        ReportServerIdPDU.decode_request(data)


def test_encode_response() -> None:
    """Test encode_response produces the correct bytes for ON/OFF status and additional data."""
    pdu = ReportServerIdPDU()
    value = ServerIdResponse(server_id=b"abc", run_indicator_status=True, additional_data=b"xyz")
    encoded = pdu.encode_response(value)
    # Should match the make_response helper
    expected = make_response(pdu.function_code, b"abc", ID_ON, b"xyz")
    assert encoded == expected

    value = ServerIdResponse(server_id=b"", run_indicator_status=False, additional_data=b"")
    encoded = pdu.encode_response(value)
    expected = make_response(pdu.function_code, b"", ID_OFF, b"")
    assert encoded == expected


def test_encode_response_boundary_byte_count() -> None:
    """Test encode_response accepts the maximum byte count of 255."""
    pdu = ReportServerIdPDU()
    value = ServerIdResponse(server_id=b"\x01" * 254, run_indicator_status=True, additional_data=b"")
    encoded = pdu.encode_response(value)
    assert encoded[1] == 255
    assert len(encoded) == 257


def test_encode_response_byte_count_too_high() -> None:
    """Test encode_response raises when the byte count exceeds 255."""
    pdu = ReportServerIdPDU()
    value = ServerIdResponse(server_id=b"\x01" * 255, run_indicator_status=True, additional_data=b"")
    with pytest.raises(ValueError, match="Server ID response byte count 256 exceeds the maximum of 255"):
        pdu.encode_response(value)


def test_encode_response_server_id_with_status_bytes_rejected() -> None:
    """Test encode_response rejects a server ID containing 0x00 or 0xFF bytes."""
    pdu = ReportServerIdPDU()
    for server_id in (b"a\x00b", b"a\xffb"):
        value = ServerIdResponse(server_id=server_id, run_indicator_status=True, additional_data=b"")
        with pytest.raises(ValueError, match="Server ID must not contain 0x00 or 0xFF bytes"):
            pdu.encode_response(value)


# --- Diagnostics Sub-Function PDU Tests ---
def test_diagnostics_query_data_encode_decode() -> None:
    """Test DiagnosticsQueryDataPDU encoding and decoding."""
    pdu = DiagnosticsQueryDataPDU(b"\xa5\x37")
    encoded = pdu.encode_request()
    assert encoded == b"\x08\x00\x00\xa5\x37"

    decoded_req = DiagnosticsQueryDataPDU.decode_request(encoded)
    assert decoded_req.data == b"\xa5\x37"

    resp_encoded = pdu.encode_response(b"\xa5\x37")
    assert resp_encoded == b"\x08\x00\x00\xa5\x37"

    resp_decoded = pdu.decode_response(resp_encoded)
    assert resp_decoded == b"\xa5\x37"

    # Odd length validation
    with pytest.raises(ValueError, match="even number of bytes"):
        DiagnosticsQueryDataPDU(b"\xa5")


def test_diagnostics_restart_communications_option() -> None:
    """Test DiagnosticsRestartCommunicationsOptionPDU encoding and decoding."""
    pdu = DiagnosticsRestartCommunicationsOptionPDU(clear_event_log=True)
    assert pdu.encode_request() == b"\x08\x00\x01\xff\x00"

    decoded_req = DiagnosticsRestartCommunicationsOptionPDU.decode_request(b"\x08\x00\x01\xff\x00")
    assert decoded_req.clear_event_log is True

    assert pdu.encode_response(True) == b"\x08\x00\x01\xff\x00"  # noqa: FBT003
    assert pdu.decode_response(b"\x08\x00\x01\xff\x00") is True


def test_diagnostics_diagnostic_register() -> None:
    """Test DiagnosticsDiagnosticRegisterPDU encoding and decoding."""
    pdu = DiagnosticsDiagnosticRegisterPDU()
    assert pdu.encode_request() == b"\x08\x00\x02\x00\x00"

    decoded_req = DiagnosticsDiagnosticRegisterPDU.decode_request(b"\x08\x00\x02\x00\x00")
    assert isinstance(decoded_req, DiagnosticsDiagnosticRegisterPDU)

    assert pdu.encode_response(0x1234) == b"\x08\x00\x02\x12\x34"
    assert pdu.decode_response(b"\x08\x00\x02\x12\x34") == 0x1234


def test_diagnostics_change_ascii_input_delimiter() -> None:
    """Test DiagnosticsChangeAsciiInputDelimiterPDU encoding and decoding."""
    pdu = DiagnosticsChangeAsciiInputDelimiterPDU(delimiter=0x0A)
    assert pdu.encode_request() == b"\x08\x00\x03\x0a\x00"

    decoded_req = DiagnosticsChangeAsciiInputDelimiterPDU.decode_request(b"\x08\x00\x03\x0a\x00")
    assert decoded_req.delimiter == 0x0A

    assert pdu.encode_response(0x0A) == b"\x08\x00\x03\x0a\x00"
    assert pdu.decode_response(b"\x08\x00\x03\x0a\x00") == 0x0A


def test_diagnostics_force_listen_only_mode() -> None:
    """Test DiagnosticsForceListenOnlyModePDU behavior (no response expected)."""
    pdu = DiagnosticsForceListenOnlyModePDU()
    assert pdu.expects_response is False
    assert pdu.encode_request() == b"\x08\x00\x04\x00\x00"
    pdu.get_broadcast_response()

    decoded_req = DiagnosticsForceListenOnlyModePDU.decode_request(b"\x08\x00\x04\x00\x00")
    assert isinstance(decoded_req, DiagnosticsForceListenOnlyModePDU)


def test_all_diagnostic_classes_full_coverage() -> None:
    """Test encode_request, decode_request, encode_response, decode_response for all diagnostic classes."""
    # Fixed at sub-function (2) + query data (2), however much has been buffered.
    assert DiagnosticsQueryDataPDU.get_expected_response_data_length(b"\x00") is None
    assert DiagnosticsQueryDataPDU.get_expected_response_data_length(b"\x00\x00") == 4
    assert DiagnosticsQueryDataPDU.get_expected_request_data_length(b"\x00\x00") == 4
    assert DiagnosticsQueryDataPDU.get_expected_response_data_length(b"\x00\x00\x12\x34") == 4
    assert DiagnosticsQueryDataPDU.get_expected_request_data_length(b"\x00\x00\x12\x34") == 4
    assert DiagnosticsQueryDataPDU.get_expected_response_data_length(b"\x00\x00\xa5\x37\xda\x8d") == 4
    assert DiagnosticsQueryDataPDU.get_expected_request_data_length(b"\x00\x00\xa5\x37\xda\x8d") == 4

    # Listen only mode response
    p_listen = DiagnosticsForceListenOnlyModePDU()
    assert p_listen.encode_request() == b"\x08\x00\x04\x00\x00"
    assert p_listen.encode_response() == b""

    with pytest.raises(InvalidResponseError):
        p_listen.decode_response(b"\x08\x00\x04\x00\x00")

    # Clear counters and register
    p_clear = DiagnosticsClearCountersAndRegisterPDU()
    assert p_clear.encode_request() == b"\x08\x00\x0a\x00\x00"
    assert p_clear.encode_response() == b"\x08\x00\x0a\x00\x00"
    p_clear.decode_response(b"\x08\x00\x0a\x00\x00")
    assert isinstance(
        DiagnosticsClearCountersAndRegisterPDU.decode_request(b"\x08\x00\x0a\x00\x00"),
        DiagnosticsClearCountersAndRegisterPDU,
    )

    # Clear overrun counter and flag
    p_overrun = DiagnosticsClearOverrunCounterAndFlagPDU()
    assert p_overrun.encode_request() == b"\x08\x00\x14\x00\x00"
    assert p_overrun.encode_response() == b"\x08\x00\x14\x00\x00"
    p_overrun.decode_response(b"\x08\x00\x14\x00\x00")
    assert isinstance(
        DiagnosticsClearOverrunCounterAndFlagPDU.decode_request(b"\x08\x00\x14\x00\x00"),
        DiagnosticsClearOverrunCounterAndFlagPDU,
    )

    # All counter classes
    counter_classes = [
        DiagnosticsBusMessageCountPDU,
        DiagnosticsBusCommunicationErrorCountPDU,
        DiagnosticsBusExceptionErrorCountPDU,
        DiagnosticsServerMessageCountPDU,
        DiagnosticsServerNoResponseCountPDU,
        DiagnosticsServerNakCountPDU,
        DiagnosticsServerBusyCountPDU,
        DiagnosticsBusCharacterOverrunCountPDU,
    ]
    for cls in counter_classes:
        inst = cls()
        req_bytes = inst.encode_request()
        dec_req = cls.decode_request(req_bytes)
        assert isinstance(dec_req, cls)
        resp_bytes = inst.encode_response(100)
        dec_resp = inst.decode_response(resp_bytes)
        assert dec_resp == 100


def test_diagnostics_listen_only_error_paths() -> None:
    """Test error validation paths for query data and restart options."""
    with pytest.raises(InvalidRequestError, match="Request length"):
        DiagnosticsForceListenOnlyModePDU.decode_request(b"\x08\x00")
    with pytest.raises(InvalidRequestError, match="Invalid function/sub-function"):
        DiagnosticsForceListenOnlyModePDU.decode_request(b"\x08\x00\x01\x00\x00")


def test_diagnostics_query_and_restart_error_paths() -> None:
    """Test error validation paths for query data and restart options."""
    # DiagnosticsQueryDataPDU error paths
    with pytest.raises(ValueError, match="even number of bytes"):
        DiagnosticsQueryDataPDU(b"\x01")
    q_pdu = DiagnosticsQueryDataPDU()
    with pytest.raises(ValueError, match="does not match request length"):
        q_pdu.encode_response(b"\x01")
    with pytest.raises(ValueError, match="response length 4 does not match request length 2"):
        q_pdu.encode_response(b"\x12\x34\x56\x78")
    with pytest.raises(InvalidRequestError, match="too short"):
        DiagnosticsQueryDataPDU.decode_request(b"\x08\x00")
    with pytest.raises(InvalidRequestError, match="Invalid function/sub-function"):
        DiagnosticsQueryDataPDU.decode_request(b"\x08\x00\x01\x00\x00")
    with pytest.raises(InvalidRequestError, match="even number of bytes"):
        DiagnosticsQueryDataPDU.decode_request(b"\x08\x00\x00\x01")
    with pytest.raises(InvalidResponseError, match="too short"):
        q_pdu.decode_response(b"\x08\x00")
    with pytest.raises(FunctionCodeError, match="Invalid function/sub-function"):
        q_pdu.decode_response(b"\x08\x00\x01\x00\x00")
    with pytest.raises(InvalidResponseError, match="even number of bytes"):
        q_pdu.decode_response(b"\x08\x00\x00\x01")

    # DiagnosticsRestartCommunicationsOptionPDU error paths
    r_pdu = DiagnosticsRestartCommunicationsOptionPDU()
    with pytest.raises(InvalidRequestError, match="Request length"):
        DiagnosticsRestartCommunicationsOptionPDU.decode_request(b"\x08\x00\x01")
    with pytest.raises(InvalidRequestError, match="Invalid function/sub-function"):
        DiagnosticsRestartCommunicationsOptionPDU.decode_request(b"\x08\x00\x02\x00\x00")
    with pytest.raises(InvalidRequestError, match="Invalid restart option data"):
        DiagnosticsRestartCommunicationsOptionPDU.decode_request(b"\x08\x00\x01\x12\x34")
    with pytest.raises(InvalidResponseError, match="Response length"):
        r_pdu.decode_response(b"\x08\x00\x01")
    with pytest.raises(FunctionCodeError, match="Invalid function/sub-function"):
        r_pdu.decode_response(b"\x08\x00\x02\x00\x00")
    with pytest.raises(InvalidResponseError, match="Invalid restart option response data"):
        r_pdu.decode_response(b"\x08\x00\x01\x12\x34")


def test_diagnostics_register_counter_error_paths() -> None:
    """Test error validation paths for diagnostic register, delimiter, and counters."""
    # DiagnosticsDiagnosticRegisterPDU error paths
    d_pdu = DiagnosticsDiagnosticRegisterPDU()
    with pytest.raises(InvalidRequestError, match="Request length"):
        DiagnosticsDiagnosticRegisterPDU.decode_request(b"\x08\x00\x02")
    with pytest.raises(InvalidRequestError, match="Invalid function/sub-function"):
        DiagnosticsDiagnosticRegisterPDU.decode_request(b"\x08\x00\x01\x00\x00")
    with pytest.raises(ValueError, match="out of range"):
        d_pdu.encode_response(0x10000)
    with pytest.raises(InvalidResponseError, match="Response length"):
        d_pdu.decode_response(b"\x08\x00\x02")
    with pytest.raises(FunctionCodeError, match="Invalid function/sub-function"):
        d_pdu.decode_response(b"\x08\x00\x01\x00\x00")

    # DiagnosticsChangeAsciiInputDelimiterPDU error paths
    with pytest.raises(ValueError, match="out of range"):
        DiagnosticsChangeAsciiInputDelimiterPDU(256)
    c_pdu = DiagnosticsChangeAsciiInputDelimiterPDU()
    with pytest.raises(ValueError, match="out of range"):
        c_pdu.encode_response(256)
    with pytest.raises(InvalidRequestError, match="Request length"):
        DiagnosticsChangeAsciiInputDelimiterPDU.decode_request(b"\x08\x00\x03")
    with pytest.raises(InvalidRequestError, match="Invalid function/sub-function"):
        DiagnosticsChangeAsciiInputDelimiterPDU.decode_request(b"\x08\x00\x01\x00\x00")
    with pytest.raises(InvalidResponseError, match="Response length"):
        c_pdu.decode_response(b"\x08\x00\x03")
    with pytest.raises(FunctionCodeError, match="Invalid function/sub-function"):
        c_pdu.decode_response(b"\x08\x00\x01\x00\x00")

    # DiagnosticsForceListenOnlyModePDU & DiagnosticsClearCountersAndRegisterPDU & ClearOverrun error paths
    for pdu_cls in (
        DiagnosticsClearCountersAndRegisterPDU,
        DiagnosticsClearOverrunCounterAndFlagPDU,
    ):
        inst = pdu_cls()
        with pytest.raises(InvalidRequestError, match="Request length"):
            pdu_cls.decode_request(b"\x08\x00")
        with pytest.raises(InvalidRequestError, match="Invalid function/sub-function"):
            pdu_cls.decode_request(b"\x08\xff\xff\x00\x00")
        with pytest.raises(InvalidResponseError, match="Response length"):
            inst.decode_response(b"\x08\x00")
        with pytest.raises(FunctionCodeError, match="Invalid function/sub-function"):
            inst.decode_response(b"\x08\xff\xff\x00\x00")

    # BaseDiagnosticsCounterPDU error paths
    cnt_pdu = DiagnosticsBusMessageCountPDU()
    with pytest.raises(InvalidRequestError, match="Request length"):
        DiagnosticsBusMessageCountPDU.decode_request(b"\x08\x00\x0b")
    with pytest.raises(InvalidRequestError, match="Invalid function/sub-function"):
        DiagnosticsBusMessageCountPDU.decode_request(b"\x08\x00\x01\x00\x00")
    with pytest.raises(ValueError, match=r"Counter value .* out of range"):
        cnt_pdu.encode_response(0x10000)
    with pytest.raises(InvalidResponseError, match="Response length"):
        cnt_pdu.decode_response(b"\x08\x00\x0b")
    with pytest.raises(FunctionCodeError, match="Invalid function/sub-function"):
        cnt_pdu.decode_response(b"\x08\x00\x01\x00\x00")


# --- GetCommEventCounterPDU (FC0B) Tests ---


def test_get_comm_event_counter_encode_decode() -> None:
    """Test GetCommEventCounterPDU encoding and decoding."""
    pdu = GetCommEventCounterPDU()
    assert pdu.encode_request() == b"\x0b"

    decoded_req = GetCommEventCounterPDU.decode_request(b"\x0b")
    assert isinstance(decoded_req, GetCommEventCounterPDU)

    with pytest.raises(InvalidRequestError, match="Expected request with only function code"):
        GetCommEventCounterPDU.decode_request(b"\x0b\x00")

    with pytest.raises(InvalidRequestError, match="Invalid function code"):
        GetCommEventCounterPDU.decode_request(b"\x0c")

    resp_val = CommEventCounterResponse(status=0xFFFF, event_count=264)
    encoded_resp = pdu.encode_response(resp_val)
    assert encoded_resp == b"\x0b\xff\xff\x01\x08"

    decoded_resp = pdu.decode_response(encoded_resp)
    assert decoded_resp == resp_val

    with pytest.raises(InvalidResponseError, match="does not match expected 5"):
        pdu.decode_response(b"\x0b\xff\xff\x01")

    with pytest.raises(FunctionCodeError, match="Invalid function code"):
        pdu.decode_response(b"\x8b\xff\xff\x01\x08")

    assert pdu.encode_response(CommEventCounterResponse(status=0x0000, event_count=0)) == b"\x0b\x00\x00\x00\x00"

    with pytest.raises(ValueError, match="Status 0x1234 invalid, expected 0x0000 or 0xFFFF"):
        pdu.encode_response(CommEventCounterResponse(status=0x1234, event_count=0))
    with pytest.raises(ValueError, match=r"Event count -1 out of range \(0-65535\)"):
        pdu.encode_response(CommEventCounterResponse(status=0x0000, event_count=-1))
    with pytest.raises(ValueError, match=r"Event count 65536 out of range \(0-65535\)"):
        pdu.encode_response(CommEventCounterResponse(status=0x0000, event_count=0x10000))

    # Decoding stays lenient: devices in the wild send other status values.
    assert pdu.decode_response(b"\x0b\x12\x34\x00\x01") == CommEventCounterResponse(status=0x1234, event_count=1)


# --- GetCommEventLogPDU (FC0C) Tests ---


def test_get_comm_event_log_encode_decode() -> None:
    """Test GetCommEventLogPDU encoding and decoding."""
    pdu = GetCommEventLogPDU()
    assert pdu.encode_request() == b"\x0c"

    decoded_req = GetCommEventLogPDU.decode_request(b"\x0c")
    assert isinstance(decoded_req, GetCommEventLogPDU)

    with pytest.raises(InvalidRequestError, match="Expected request with only function code"):
        GetCommEventLogPDU.decode_request(b"\x0c\x00")

    with pytest.raises(InvalidRequestError, match="Invalid function code"):
        GetCommEventLogPDU.decode_request(b"\x0d")

    resp_val = CommEventLogResponse(status=0x0000, event_count=264, message_count=289, events=b"\x20\x00")
    encoded_resp = pdu.encode_response(resp_val)
    assert encoded_resp == b"\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00"

    decoded_resp = pdu.decode_response(encoded_resp)
    assert decoded_resp == resp_val

    # Response too short
    with pytest.raises(InvalidResponseError, match="too short"):
        pdu.decode_response(b"\x0c\x08\x00\x00\x01")

    # Mismatched length
    with pytest.raises(InvalidResponseError, match="does not match expected"):
        pdu.decode_response(b"\x0c\x08\x00\x00\x01\x08\x01\x21\x20")

    # Invalid function code
    with pytest.raises(FunctionCodeError, match="Invalid function code"):
        pdu.decode_response(b"\x8c\x08\x00\x00\x01\x08\x01\x21\x20\x00")

    # The 64-event maximum is accepted; one more is rejected.
    max_events = CommEventLogResponse(status=0, event_count=0, message_count=0, events=b"\x20" * 64)
    assert pdu.decode_response(pdu.encode_response(max_events)) == max_events

    too_many = CommEventLogResponse(status=0, event_count=0, message_count=0, events=b"\x20" * 65)
    with pytest.raises(ValueError, match="Comm event log length 65 exceeds the maximum of 64"):
        pdu.encode_response(too_many)

    # Decoding stays lenient for devices that report more than 64 events.
    lenient = b"\x0c\x47\x00\x00\x00\x00\x00\x00" + b"\x20" * 65
    assert pdu.decode_response(lenient).events == b"\x20" * 65
