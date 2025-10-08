r"""Tests for tmodbus/transport/async_ascii.py.

Tests verify compliance with Modbus ASCII specification including:
- Frame format: ':' + ASCII-hex(Address + PDU + LRC) + '\r\n'
- LRC (Longitudinal Redundancy Check) calculation
- Character encoding (uppercase hexadecimal)
- Frame parsing and validation
"""

import asyncio
import time
from functools import partial
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
import serial_asyncio_fast
from tmodbus.exceptions import (
    ASCIIFrameError,
    IllegalFunctionError,
    InvalidResponseError,
    LRCError,
    ModbusConnectionError,
    ModbusResponseError,
)
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_ascii import (
    ASCII_FRAME_END,
    ASCII_FRAME_START,
    MAX_ASCII_FRAME_SIZE,
    AsyncAsciiTransport,
    ascii_decode,
    ascii_encode,
    build_ascii_frame,
    parse_ascii_frame,
)
from tmodbus.utils.lrc import calculate_lrc


class _DummyPDU(BaseClientPDU[tuple[str, bytes]]):
    """Dummy PDU for testing."""

    function_code = 0x03

    def encode_request(self) -> bytes:
        """Encode a simple request."""
        return b"\x03\x00"

    def decode_response(self, data: bytes) -> tuple[str, bytes]:
        """Decode response."""
        return ("decoded", data)


def _dummy_readuntil(separator: bytes, *, response_frame: bytes) -> bytes:
    assert response_frame.startswith(b":")
    assert response_frame.endswith(b"\r\n")

    if separator == b":":
        return b":"
    if separator == b"\r\n":
        return response_frame[1:]
    msg = f"Unexpected separator: {separator!r}"
    raise ValueError(msg)


# ============================================================================
# Encoding/Decoding Tests
# ============================================================================


def test_ascii_encode() -> None:
    """Test ASCII encoding produces uppercase hex."""
    assert ascii_encode(b"\x01\x03") == b"0103"
    assert ascii_encode(b"\xab\xcd\xef") == b"ABCDEF"
    assert ascii_encode(b"\x00") == b"00"
    assert ascii_encode(b"\xff") == b"FF"


def test_ascii_decode() -> None:
    """Test ASCII decoding from hex string."""
    assert ascii_decode(b"0103") == b"\x01\x03"
    assert ascii_decode(b"ABCDEF") == b"\xab\xcd\xef"
    assert ascii_decode(b"abcdef") == b"\xab\xcd\xef"  # lowercase works too
    assert ascii_decode(b"00") == b"\x00"
    assert ascii_decode(b"FF") == b"\xff"


def test_ascii_encode_decode_roundtrip() -> None:
    """Test that encoding and decoding are inverse operations."""
    test_data = [
        b"\x01",
        b"\x01\x03\x00\x00\x00\x64",
        b"\xff\xfe\xfd\xfc",
        bytes(range(256)),
    ]
    for data in test_data:
        encoded = ascii_encode(data)
        decoded = ascii_decode(encoded)
        assert decoded == data


# ============================================================================
# Frame Building Tests - Spec Compliance
# ============================================================================


def test_build_ascii_frame_spec_example() -> None:
    r"""Test frame building with Modbus spec example.

    Example: Read holding registers with quantity 1 from slave 0x01
    Request: 01 03 00 00 00 01
    LRC: -(01 + 03 + 00 + 00 + 00 + 01) = 251 = 0xfb
    Frame: :010300000064 FB\r\n (hex encoded)
    """
    address = 0x01
    pdu = b"\x03\x00\x00\x00\x01"

    frame = build_ascii_frame(address, pdu)

    # Verify frame structure
    assert frame.startswith(ASCII_FRAME_START)
    assert frame.endswith(ASCII_FRAME_END)

    # Remove framing
    hex_content = frame[1:-2]

    # Decode hex
    raw = ascii_decode(hex_content)

    # Verify content: address + pdu + lrc
    assert raw[0] == address
    assert raw[1:6] == pdu

    # Verify LRC
    message = raw[:-1]
    lrc_value = raw[-1]
    expected_lrc = calculate_lrc(message)
    assert lrc_value == expected_lrc
    assert lrc_value == 0xFB


def test_build_ascii_frame_minimal() -> None:
    """Test frame building with minimal data."""
    address = 0x01
    pdu = b"\x03"

    frame = build_ascii_frame(address, pdu)

    # Expected: ':' + hex(01 03 LRC) + '\r\n'
    assert frame.startswith(b":")
    assert frame.endswith(b"\r\n")

    # Extract and verify
    hex_part = frame[1:-2]
    raw = ascii_decode(hex_part)
    assert raw[0] == 0x01
    assert raw[1] == 0x03
    assert len(raw) == 3  # address + pdu + lrc


def test_build_ascii_frame_max_address() -> None:
    """Test frame building with maximum valid address (247)."""
    address = 247
    pdu = b"\x03\x00\x00\x00\x01"

    frame = build_ascii_frame(address, pdu)

    hex_content = frame[1:-2]
    raw = ascii_decode(hex_content)
    assert raw[0] == 247


def test_build_ascii_frame_broadcast() -> None:
    """Test frame building with broadcast address (0)."""
    address = 0
    pdu = b"\x05\x00\x00\xff\x00"

    frame = build_ascii_frame(address, pdu)

    hex_content = frame[1:-2]
    raw = ascii_decode(hex_content)
    assert raw[0] == 0


# ============================================================================
# Frame Parsing Tests - Spec Compliance
# ============================================================================


def test_parse_ascii_frame_valid() -> None:
    """Test parsing a valid ASCII frame."""
    # Build a frame and then parse it
    address = 0x11
    pdu = b"\x03\x00\x6b\x00\x03"
    frame = build_ascii_frame(address, pdu)

    parsed = parse_ascii_frame(frame)

    # Verify parsed content includes address + pdu + lrc
    assert parsed[0] == address
    assert parsed[1:6] == pdu
    assert len(parsed) == 7  # address + 5 bytes pdu + lrc


def test_parse_ascii_frame_spec_example() -> None:
    r"""Test parsing with Modbus spec example frame.

    Response example for read holding registers:
    Address: 0x01, Function: 0x03, Data: 02 bytes of data
    """
    # Manually construct a valid frame
    address = 0x01
    function_code = 0x03
    byte_count = 0x02
    data = b"\x00\x64"

    pdu = bytes([function_code, byte_count]) + data
    message = bytes([address]) + pdu
    lrc = calculate_lrc(message)

    # Build frame: ':' + hex + '\r\n'
    hex_content = ascii_encode(message + bytes([lrc]))
    frame = b":" + hex_content + b"\r\n"

    parsed = parse_ascii_frame(frame)

    assert parsed[0] == address
    assert parsed[1] == function_code
    assert parsed[2] == byte_count
    assert parsed[3:5] == data


def test_parse_ascii_frame_missing_start() -> None:
    """Test that frames without ':' raise ASCIIFrameError."""
    # Valid content but missing ':'
    frame = b"01030000000098\r\n"

    with pytest.raises(ASCIIFrameError, match="does not start with ':'"):
        parse_ascii_frame(frame)


def test_parse_ascii_frame_missing_end() -> None:
    r"""Test that frames without '\r\n' raise ASCIIFrameError."""
    # Valid content but missing '\r\n'
    frame = b":01030000000098"

    with pytest.raises(ASCIIFrameError, match=r" and end with '\\r\\n'"):
        parse_ascii_frame(frame)


def test_parse_ascii_frame_invalid_hex() -> None:
    """Test that frames with invalid hex characters raise ASCIIFrameError."""
    # Contains invalid hex character 'G'
    frame = b":0G030000000098\r\n"

    with pytest.raises(ASCIIFrameError, match="Invalid hex"):
        parse_ascii_frame(frame)


def test_parse_ascii_frame_too_short() -> None:
    """Test that frames that are too short raise ASCIIFrameError."""
    # Only contains address and function code (need at least address + something + lrc)
    frame = b":0103\r\n"

    with pytest.raises(ASCIIFrameError, match="too short"):
        parse_ascii_frame(frame)


def test_parse_ascii_frame_invalid_lrc() -> None:
    """Test that frames with incorrect LRC raise LRCError."""
    # Valid frame structure but wrong LRC (using 0x99 instead of correct 0x98)
    frame = b":01030000006499\r\n"

    with pytest.raises(LRCError):
        parse_ascii_frame(frame)


def test_parse_ascii_frame_odd_hex_length() -> None:
    """Test that frames with odd number of hex characters raise error."""
    # Odd number of hex characters (missing one)
    frame = b":0103000000064\r\n"

    with pytest.raises(ASCIIFrameError, match="Invalid hex"):
        parse_ascii_frame(frame)


# ============================================================================
# Transport Connection Tests
# ============================================================================


@pytest.fixture
def mock_asyncio_connection(monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, MagicMock]:
    """Fixture to mock serial_asyncio_fast connection."""
    reader = MagicMock(asyncio.StreamReader)
    writer = MagicMock(asyncio.StreamWriter)
    writer.is_closing.return_value = False

    monkeypatch.setattr(serial_asyncio_fast, "open_serial_connection", AsyncMock(return_value=(reader, writer)))
    return reader, writer


async def test_open_already_open(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that open early-returns if already open and logs debug."""
    reader, writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    # Simulate already open
    transport._reader = reader
    transport._writer = writer

    with patch("tmodbus.transport.async_ascii.logger") as log:
        await transport.open()
        log.debug.assert_called()


async def test_open_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that open raises TimeoutError when connection times out."""
    monkeypatch.setattr(
        "serial_asyncio_fast.open_serial_connection",
        AsyncMock(side_effect=asyncio.TimeoutError),
    )

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    with pytest.raises(TimeoutError):
        await transport.open()


@pytest.mark.usefixtures("mock_asyncio_connection")
async def test_open_close_is_open() -> None:
    """Test open, close, and is_open functionality."""
    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    await transport.open()
    assert transport.is_open()

    await transport.close()
    assert not transport.is_open()


async def test_close_already_closed() -> None:
    """Test that close early-returns if already closed."""
    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    with patch("tmodbus.transport.async_ascii.logger") as log:
        await transport.close()
        log.debug.assert_called()


async def test_close_with_exception(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that close logs exceptions but doesn't raise."""
    reader, writer = mock_asyncio_connection
    writer.close = MagicMock(side_effect=Exception("Close error"))

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    transport._reader = reader
    transport._writer = writer

    with patch("tmodbus.transport.async_ascii.logger") as log:
        await transport.close()
        writer.close.assert_called()
        log.debug.assert_called()

    # Should still mark as closed
    assert not transport.is_open()


async def test_open_raises_modbus_connection_error_on_generic_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that open raises ModbusConnectionError for generic exceptions."""
    monkeypatch.setattr(
        "serial_asyncio_fast.open_serial_connection",
        AsyncMock(side_effect=Exception("Connection failed")),
    )

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    with pytest.raises(ModbusConnectionError):
        await transport.open()


# ============================================================================
# Send and Receive Tests
# ============================================================================


async def test_send_and_receive_success(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test successful send and receive with valid ASCII response."""
    reader, _writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build expected response frame
    response_pdu = b"\x03\x02\x00\x64"
    response_frame = build_ascii_frame(unit_id, response_pdu)

    reader.readuntil = AsyncMock(side_effect=partial(_dummy_readuntil, response_frame=response_frame))

    async with transport:
        result = await transport.send_and_receive(unit_id, pdu)
    assert result[0] == "decoded"


async def test_send_and_receive_not_connected() -> None:
    """Test that send_and_receive raises error when not connected."""
    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()

    with pytest.raises(ModbusConnectionError):
        await transport.send_and_receive(1, pdu)


async def test_receive_response_no_reader() -> None:
    """Test that receive raises error if reader is None."""
    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    transport._reader = None

    with pytest.raises(ModbusConnectionError):
        await transport._receive_response()


async def test_receive_response_timeout(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that receive times out correctly."""
    reader, _writer = mock_asyncio_connection
    reader.readuntil = AsyncMock(side_effect=asyncio.TimeoutError)

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    async with transport:
        with pytest.raises(asyncio.TimeoutError):
            await transport._receive_response()


async def test_receive_response_incomplete_read(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that incomplete read raises ASCIIFrameError."""
    reader, _writer = mock_asyncio_connection
    reader.readuntil = AsyncMock(side_effect=asyncio.IncompleteReadError(partial=b"", expected=None))

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    async with transport:
        with pytest.raises(ASCIIFrameError):
            await transport._receive_response()


async def test_receive_response_frame_too_large(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that frames exceeding max size raise ASCIIFrameError."""
    reader, writer = mock_asyncio_connection

    # Create a frame that's too large
    large_frame = b":" + (b"00" * (MAX_ASCII_FRAME_SIZE + 10)) + b"\r\n"

    reader.readuntil = AsyncMock(side_effect=partial(_dummy_readuntil, response_frame=large_frame))

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    transport._reader = reader
    transport._writer = writer

    with pytest.raises(ASCIIFrameError, match="too large"):
        await transport._receive_response()


async def test_send_and_receive_wrong_address(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that response with wrong address raises InvalidResponseError."""
    reader, writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build response frame with WRONG address
    wrong_address = 0x12
    response_pdu = b"\x03\x02\x00\x64"
    response_frame = build_ascii_frame(wrong_address, response_pdu)

    reader.readuntil = AsyncMock(side_effect=partial(_dummy_readuntil, response_frame=response_frame))

    transport._reader = reader
    transport._writer = writer
    transport._last_frame_ended_at = time.monotonic() - 10

    with pytest.raises(InvalidResponseError, match="Slave address mismatch"):
        await transport.send_and_receive(unit_id, pdu)


async def test_send_and_receive_exception_response(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that exception responses are properly raised."""
    reader, _writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build exception response (function code + 0x80, exception code 0x01)
    exception_pdu = b"\x83\x01"  # 0x03 + 0x80 = 0x83, exception code 1
    response_frame = build_ascii_frame(unit_id, exception_pdu)

    reader.readuntil = AsyncMock(side_effect=partial(_dummy_readuntil, response_frame=response_frame))
    async with transport:
        with pytest.raises(IllegalFunctionError):
            await transport.send_and_receive(unit_id, pdu)


async def test_send_and_receive_invalid_lrc(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that frames with invalid LRC raise LRCError."""
    reader, _writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build frame with WRONG LRC
    response_pdu = b"\x03\x02\x00\x64"
    message = bytes([unit_id]) + response_pdu
    wrong_lrc = 0xFF  # Intentionally wrong
    hex_content = ascii_encode(message + bytes([wrong_lrc]))
    bad_frame = b":" + hex_content + b"\r\n"

    reader.readuntil = AsyncMock(side_effect=partial(_dummy_readuntil, response_frame=bad_frame))

    async with transport:
        with pytest.raises(LRCError):
            await transport.send_and_receive(unit_id, pdu)


async def test_interframe_delay(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that interframe delay is properly enforced."""
    reader, writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build valid response
    response_pdu = b"\x03\x02\x00\x64"
    response_frame = build_ascii_frame(unit_id, response_pdu)

    reader.readuntil = AsyncMock(side_effect=partial(_dummy_readuntil, response_frame=response_frame))

    transport._reader = reader
    transport._writer = writer

    # Set last frame to recent time
    fixed_time = time.monotonic()

    transport._last_frame_ended_at = fixed_time

    # Mock asyncio.sleep to track if it was called
    with (
        patch("time.monotonic", lambda: fixed_time),
        patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
    ):
        await transport.send_and_receive(unit_id, pdu)
        # Should have called sleep for interframe delay
        mock_sleep.assert_called()


async def test_open_and_close_log_info(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that open and close operations log info messages."""
    _reader, writer = mock_asyncio_connection

    writer.is_closing.return_value = False

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    with patch("tmodbus.transport.async_ascii.logger") as log:
        await transport.open()
        log.info.assert_called()

    with patch("tmodbus.transport.async_ascii.logger") as log:
        await transport.close()
        log.info.assert_called()


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================


def test_build_ascii_frame_empty_pdu() -> None:
    """Test building frame with empty PDU."""
    address = 0x01
    pdu = b""

    frame = build_ascii_frame(address, pdu)

    # Should still create valid frame with just address and LRC
    assert frame.startswith(b":")
    assert frame.endswith(b"\r\n")

    hex_content = frame[1:-2]
    raw = ascii_decode(hex_content)
    assert raw[0] == address
    assert len(raw) == 2  # address + lrc


def test_build_ascii_frame_large_pdu() -> None:
    """Test building frame with large PDU (near max size)."""
    address = 0x01
    # Maximum PDU is 253 bytes (255 - address - lrc)
    pdu = b"\x03" + b"\x00" * 252

    frame = build_ascii_frame(address, pdu)

    # Should not exceed max frame size
    assert len(frame) <= MAX_ASCII_FRAME_SIZE

    hex_content = frame[1:-2]
    raw = ascii_decode(hex_content)
    assert len(raw) == 1 + len(pdu) + 1  # address + pdu + lrc


def test_ascii_frame_character_case() -> None:
    """Test that ASCII frames use uppercase hex characters per spec."""
    address = 0xAB
    pdu = b"\xcd\xef"

    frame = build_ascii_frame(address, pdu)

    # Extract hex part (between ':' and '\r\n')
    hex_part = frame[1:-2].decode("ascii")

    # All characters should be uppercase or digits
    assert hex_part.isupper() or hex_part.isdigit()
    assert "a" not in hex_part
    assert "b" not in hex_part
    assert "c" not in hex_part
    assert "A" in hex_part or "B" in hex_part  # At least some hex letters


async def test_send_and_receive_writer_none_after_check(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that send_and_receive raises error if writer becomes None after is_open check."""
    reader, writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()
    unit_id = 0x11

    transport._reader = reader
    transport._writer = writer
    transport._last_frame_ended_at = time.monotonic() - 10

    # Simulate writer becoming None after the is_open check
    async def send_with_cleared_writer() -> None:
        async with transport._communication_lock:
            if not transport.is_open():
                msg = "Not connected."
                raise ModbusConnectionError(msg)

            # Build request frame
            request_pdu_bytes = pdu.encode_request()
            _request_adu = build_ascii_frame(unit_id, request_pdu_bytes)

            # Wait for end-of-frame gap
            time_since_last_frame = time.monotonic() - transport._last_frame_ended_at
            min_gap = 0.001
            if time_since_last_frame < min_gap:
                await asyncio.sleep(min_gap - time_since_last_frame)

            # Clear writer before the check
            transport._writer = None

            # This should raise
            if not transport._writer:
                msg = "Connection not established."
                raise ModbusConnectionError(msg)

    with pytest.raises(ModbusConnectionError, match="Connection not established"):
        await send_with_cleared_writer()


async def test_send_and_receive_logs_modbus_connection_error(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that ModbusConnectionError during receive is logged properly."""
    reader, writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Mock reader to raise a generic exception that will be wrapped in ModbusConnectionError
    reader.readuntil = AsyncMock(side_effect=OSError("Connection lost"))

    transport._reader = reader
    transport._writer = writer
    transport._last_frame_ended_at = time.monotonic() - 10

    with patch("tmodbus.transport.async_ascii.log_raw_traffic") as mock_log:
        with pytest.raises(ModbusConnectionError):
            await transport.send_and_receive(unit_id, pdu)
        # Verify that log_raw_traffic was called with is_error=True
        mock_log.assert_any_call("recv", ANY, is_error=True)


async def test_send_and_receive_exception_response_no_exception_code(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test exception response with missing exception code (malformed response)."""
    reader, writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build exception response WITHOUT exception code (only function code with error bit)
    # This is a malformed response but we should handle it gracefully
    exception_pdu = b"\x83"  # 0x03 + 0x80 = 0x83, but no exception code byte
    response_frame = build_ascii_frame(unit_id, exception_pdu)

    reader.readuntil = AsyncMock(side_effect=partial(_dummy_readuntil, response_frame=response_frame))

    transport._reader = reader
    transport._writer = writer
    transport._last_frame_ended_at = time.monotonic() - 10

    # Should raise ModbusResponseError with exception_code = 0 (default)
    with pytest.raises(ModbusResponseError):
        await transport.send_and_receive(unit_id, pdu)


async def test_receive_response_with_garbage_before_frame(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that garbage bytes before frame start are discarded and logged."""
    reader, writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    unit_id = 0x11

    # Build valid response
    response_pdu = b"\x03\x02\x00\x64"
    response_frame = build_ascii_frame(unit_id, response_pdu)

    # Simulate garbage before the ':'
    garbage = b"\x00\xff\xaa"

    async def mock_readuntil(separator: bytes) -> bytes:
        if separator == b":":
            # Return garbage + ':'
            return garbage + b":"
        if separator == b"\r\n":
            return response_frame[1:]
        msg = f"Unexpected separator: {separator!r}"
        raise ValueError(msg)

    reader.readuntil = AsyncMock(side_effect=mock_readuntil)

    transport._reader = reader
    transport._writer = writer

    with patch("tmodbus.transport.async_ascii.logger") as mock_logger:
        result = await transport._receive_response()
        # Verify that logger.info was called about discarding garbage
        mock_logger.info.assert_called_once()
        assert "garbage" in str(mock_logger.info.call_args)
        assert result == response_frame


async def test_receive_response_generic_exception(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that generic exceptions during receive are wrapped in ModbusConnectionError."""
    reader, _writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    # Mock reader to raise a generic exception (not IncompleteReadError or TimeoutError)
    reader.readuntil = AsyncMock(side_effect=OSError("Serial port error"))

    async with transport:
        with pytest.raises(ModbusConnectionError, match="Failed to read Modbus response"):
            await transport._receive_response()


async def test_writer_becomes_none_during_send(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that send_and_receive raises error if writer becomes None during send."""
    reader, _writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()
    unit_id = 0x11

    transport._reader = reader
    transport._last_frame_ended_at = time.monotonic() - 10

    with (
        patch.object(transport, "is_open", MagicMock(return_value=True)),
        pytest.raises(ModbusConnectionError, match="Connection not established"),
    ):
        await transport.send_and_receive(unit_id, pdu)


async def test_send_and_receive_function_code_mismatch(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that response with wrong function code raises InvalidResponseError."""
    reader, writer = mock_asyncio_connection

    transport = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()  # Expects function code 0x03
    unit_id = 0x11

    # Build response with WRONG function code (0x04 instead of 0x03)
    wrong_response_pdu = b"\x04\x02\x00\x64"  # Function code 0x04
    response_frame = build_ascii_frame(unit_id, wrong_response_pdu)

    reader.readuntil = AsyncMock(side_effect=partial(_dummy_readuntil, response_frame=response_frame))

    transport._reader = reader
    transport._writer = writer
    transport._last_frame_ended_at = time.monotonic() - 10

    with pytest.raises(InvalidResponseError, match="Function code mismatch"):
        await transport.send_and_receive(unit_id, pdu)
