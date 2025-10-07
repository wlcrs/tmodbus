"""Tests for tmodbus/transport/async_rtu_over_tcp.py.

Tests verify RTU over TCP transport implementation including:
- TCP connection management
- RTU framing with CRC-16 validation
- Error handling and validation
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tmodbus.exceptions import (
    CRCError,
    IllegalFunctionError,
    InvalidResponseError,
    ModbusConnectionError,
    RTUFrameError,
)
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_rtu_over_tcp import AsyncRtuOverTcpTransport
from tmodbus.utils.crc import calculate_crc16


class _DummyPDU(BaseClientPDU[tuple[str, bytes]]):
    """Dummy PDU for testing."""

    function_code = 0x03

    def encode_request(self) -> bytes:
        """Encode a simple request."""
        return b"\x03\x00"

    def decode_response(self, data: bytes) -> tuple[str, bytes]:
        """Decode response."""
        return ("decoded", data)


# ============================================================================
# Constructor Tests
# ============================================================================


async def test_invalid_constructor_args() -> None:
    """Test that invalid constructor arguments raise ValueError."""
    with pytest.raises(ValueError, match=r"Port must be .*"):
        AsyncRtuOverTcpTransport("host", port=0)

    with pytest.raises(ValueError, match=r"Port must be .*"):
        AsyncRtuOverTcpTransport("host", port=65536)

    with pytest.raises(ValueError, match=r"Timeout must .*"):
        AsyncRtuOverTcpTransport("host", timeout=0)

    with pytest.raises(ValueError, match=r"Timeout must .*"):
        AsyncRtuOverTcpTransport("host", timeout=-1)

    with pytest.raises(ValueError, match=r"Connect timeout must .*"):
        AsyncRtuOverTcpTransport("host", connect_timeout=0)


async def test_valid_constructor() -> None:
    """Test valid constructor arguments."""
    t = AsyncRtuOverTcpTransport("localhost", port=502, timeout=5.0, connect_timeout=3.0)
    assert t.host == "localhost"
    assert t.port == 502
    assert t.timeout == 5.0
    assert t.connect_timeout == 3.0


# ============================================================================
# Connection Tests
# ============================================================================


@pytest.fixture
def mock_asyncio_connection(monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, MagicMock]:
    """Fixture to mock asyncio open_connection."""
    reader = MagicMock(asyncio.StreamReader)
    writer = MagicMock(asyncio.StreamWriter)
    writer.is_closing.return_value = False

    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
    return reader, writer


async def test_open_and_close(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test open and close functionality."""
    _reader, writer = mock_asyncio_connection
    writer.is_closing.return_value = False

    t = AsyncRtuOverTcpTransport("host", port=1234)
    await t.open()
    assert t.is_open()

    await t.close()
    assert not t.is_open()


async def test_open_already_open(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that open early-returns if already open."""
    reader, writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    t._reader = reader
    t._writer = writer

    with patch("tmodbus.transport.async_rtu_over_tcp.logger") as log:
        await t.open()
        log.debug.assert_called()


async def test_close_already_closed() -> None:
    """Test that close early-returns if already closed."""
    t = AsyncRtuOverTcpTransport("host", port=1234)

    with patch("tmodbus.transport.async_rtu_over_tcp.logger") as log:
        await t.close()
        log.debug.assert_called()


async def test_open_connection_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that connection timeout is properly raised."""
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(side_effect=asyncio.TimeoutError))

    t = AsyncRtuOverTcpTransport("host", port=1234, connect_timeout=0.1)
    with pytest.raises(asyncio.TimeoutError):
        await t.open()


async def test_open_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that connection errors during open are handled."""
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(side_effect=OSError("Connection failed")))

    t = AsyncRtuOverTcpTransport("host", port=1234)
    with pytest.raises(ModbusConnectionError):
        await t.open()


async def test_close_with_exception(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that close logs exceptions but doesn't raise."""
    reader, writer = mock_asyncio_connection
    writer.close = MagicMock(side_effect=Exception("Close error"))

    t = AsyncRtuOverTcpTransport("host", port=1234)
    t._reader = reader
    t._writer = writer

    with patch("tmodbus.transport.async_rtu_over_tcp.logger") as log:
        await t.close()
        writer.close.assert_called()
        log.debug.assert_called()

    # Should still mark as closed
    assert not t.is_open()


async def test_is_open_false_when_not_connected() -> None:
    """Test is_open returns False when not connected."""
    t = AsyncRtuOverTcpTransport("host", port=1234)
    assert not t.is_open()


# ============================================================================
# Send and Receive Tests
# ============================================================================


async def test_send_and_receive_success(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test successful send and receive with valid RTU frame."""
    reader, _writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build expected response RTU frame
    response_pdu = b"\x03\x02\x00\x64"
    response_prefix = bytes([unit_id]) + response_pdu
    crc = calculate_crc16(response_prefix)
    response_frame = response_prefix + crc

    # Mock reader to return the complete frame
    reader.readexactly = AsyncMock(return_value=response_frame)

    async with t:
        result = await t.send_and_receive(unit_id, pdu)

    assert result[0] == "decoded"
    assert result[1] == response_pdu


async def test_send_and_receive_not_connected() -> None:
    """Test that send_and_receive raises error when not connected."""
    t = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()

    with pytest.raises(ModbusConnectionError, match="Not connected"):
        await t.send_and_receive(1, pdu)


async def test_send_and_receive_writer_none(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that send_and_receive raises error if writer becomes None."""
    reader, _writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    unit_id = 0x11

    t._reader = reader
    t._writer = None  # Simulate writer being None

    with pytest.raises(ModbusConnectionError, match="Not connected"):
        await t.send_and_receive(unit_id, pdu)


async def test_send_and_receive_invalid_crc(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that frames with invalid CRC raise CRCError."""
    reader, writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build frame with WRONG CRC
    response_pdu = b"\x03\x02\x00\x64"
    response_prefix = bytes([unit_id]) + response_pdu
    bad_crc = b"\xff\xff"  # Intentionally wrong CRC
    bad_frame = response_prefix + bad_crc

    reader.readexactly = AsyncMock(return_value=bad_frame)

    t._reader = reader
    t._writer = writer

    with pytest.raises(CRCError):
        await t.send_and_receive(unit_id, pdu)


async def test_send_and_receive_wrong_address(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that response with wrong address raises InvalidResponseError."""
    reader, writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build response frame with WRONG address
    wrong_address = 0x12
    response_pdu = b"\x03\x02\x00\x64"
    response_prefix = bytes([wrong_address]) + response_pdu
    crc = calculate_crc16(response_prefix)
    response_frame = response_prefix + crc

    reader.readexactly = AsyncMock(return_value=response_frame)

    t._reader = reader
    t._writer = writer

    with pytest.raises(InvalidResponseError, match="Slave address mismatch"):
        await t.send_and_receive(unit_id, pdu)


async def test_send_and_receive_exception_response(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that exception responses are properly raised."""
    reader, _writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Build exception response (function code + 0x80, exception code 0x01)
    exception_pdu = b"\x83\x01"  # 0x03 + 0x80 = 0x83, exception code 1
    response_prefix = bytes([unit_id]) + exception_pdu
    crc = calculate_crc16(response_prefix)
    response_frame = response_prefix + crc

    reader.readexactly = AsyncMock(return_value=response_frame)

    async with t:
        with pytest.raises(IllegalFunctionError):
            await t.send_and_receive(unit_id, pdu)


async def test_send_and_receive_function_code_mismatch(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that response with wrong function code raises InvalidResponseError."""
    reader, _writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()  # Expects function code 0x03
    unit_id = 0x11

    # Build response with WRONG function code (0x04 instead of 0x03)
    wrong_response_pdu = b"\x04\x02\x00\x64"  # Function code 0x04
    response_prefix = bytes([unit_id]) + wrong_response_pdu
    crc = calculate_crc16(response_prefix)
    response_frame = response_prefix + crc

    reader.readexactly = AsyncMock(return_value=response_frame)

    t._reader = reader
    t._writer = _writer

    with pytest.raises(InvalidResponseError, match="Function code mismatch"):
        await t.send_and_receive(unit_id, pdu)


# ============================================================================
# Receive Response Tests
# ============================================================================


async def test_receive_response_reader_none() -> None:
    """Test that _receive_response raises error if reader is None."""
    t = AsyncRtuOverTcpTransport("host", port=1234)
    t._reader = None

    with pytest.raises(ModbusConnectionError, match="TCP connection not established"):
        await t._receive_response()


async def test_receive_response_incomplete_header(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that incomplete header read raises RTUFrameError."""
    reader, _writer = mock_asyncio_connection
    reader.readexactly = AsyncMock(side_effect=asyncio.IncompleteReadError(partial=b"\x01\x03", expected=4))

    t = AsyncRtuOverTcpTransport("host", port=1234)
    t._reader = reader

    with pytest.raises(RTUFrameError, match="incomplete data"):
        await t._receive_response()


async def test_receive_response_timeout(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that receive timeout is properly raised."""
    reader, _writer = mock_asyncio_connection
    reader.readexactly = AsyncMock(side_effect=asyncio.TimeoutError)

    t = AsyncRtuOverTcpTransport("host", port=1234, timeout=0.1)
    t._reader = reader

    with pytest.raises(asyncio.TimeoutError):
        await t._receive_response()


async def test_receive_response_generic_exception(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that generic exceptions are wrapped in ModbusConnectionError."""
    reader, _writer = mock_asyncio_connection
    reader.readexactly = AsyncMock(side_effect=OSError("Read error"))

    t = AsyncRtuOverTcpTransport("host", port=1234)
    t._reader = reader

    with pytest.raises(ModbusConnectionError, match="Failed to read"):
        await t._receive_response()


async def test_receive_response_frame_too_large(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that frames exceeding max size raise RTUFrameError."""
    reader, _writer = mock_asyncio_connection

    # Return a header that would indicate a very large frame
    # We'll mock the header to suggest an impossibly large data length
    large_header = b"\x01\x03\xff\xff"  # Unit 1, Function 3, huge byte count

    reader.readexactly = AsyncMock(return_value=large_header)

    t = AsyncRtuOverTcpTransport("host", port=1234)
    t._reader = reader

    with pytest.raises(RTUFrameError, match="exceeds maximum"):
        await t._receive_response()


async def test_receive_response_incomplete_remaining(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test incomplete read when receiving remaining bytes."""
    reader, _writer = mock_asyncio_connection

    # First call returns header, second call fails
    reader.readexactly = AsyncMock(
        side_effect=[
            b"\x01\x03\x02\x00",  # Header: unit 1, func 3, 2 bytes data
            asyncio.IncompleteReadError(partial=b"\x64", expected=3),  # Missing 2 bytes (1 data + 2 CRC)
        ]
    )

    t = AsyncRtuOverTcpTransport("host", port=1234)
    t._reader = reader

    with pytest.raises(RTUFrameError, match="incomplete data"):
        await t._receive_response()


async def test_context_manager(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that transport can be used as async context manager."""
    _reader, writer = mock_asyncio_connection
    writer.is_closing.return_value = False

    t = AsyncRtuOverTcpTransport("host", port=1234)

    async with t:
        assert t.is_open()

    assert not t.is_open()


async def test_logging_on_open_and_close(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    """Test that open and close operations log info messages."""
    _reader, writer = mock_asyncio_connection
    writer.is_closing.return_value = False

    t = AsyncRtuOverTcpTransport("host", port=1234)

    with patch("tmodbus.transport.async_rtu_over_tcp.logger") as log:
        await t.open()
        log.info.assert_called()

    with patch("tmodbus.transport.async_rtu_over_tcp.logger") as log:
        await t.close()
        log.info.assert_called()


async def test_send_and_receive_logs_rtu_frame_error(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that RTUFrameError during receive is logged properly."""
    reader, writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Mock reader to raise RTUFrameError with response_bytes
    reader.readexactly = AsyncMock(side_effect=asyncio.IncompleteReadError(partial=b"\x01\x03", expected=4))

    t._reader = reader
    t._writer = writer

    with patch("tmodbus.transport.async_rtu_over_tcp.log_raw_traffic") as mock_log:
        with pytest.raises(RTUFrameError):
            await t.send_and_receive(unit_id, pdu)
        # Verify that log_raw_traffic was called with is_error=True
        mock_log.assert_any_call("recv", b"\x01\x03", is_error=True)


async def test_send_and_receive_logs_modbus_connection_error_on_receive(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that ModbusConnectionError during receive is logged properly."""
    reader, writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    unit_id = 0x11

    # Mock reader to raise a generic exception that will be wrapped in ModbusConnectionError
    reader.readexactly = AsyncMock(side_effect=OSError("Connection lost"))

    t._reader = reader
    t._writer = writer

    with patch("tmodbus.transport.async_rtu_over_tcp.log_raw_traffic") as mock_log:
        with pytest.raises(ModbusConnectionError):
            await t.send_and_receive(unit_id, pdu)
        # Verify that log_raw_traffic was called with is_error=True
        mock_log.assert_any_call("recv", b"", is_error=True)


async def test_receive_response_complete_in_header(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test receiving complete response in initial header read (exception response)."""
    reader, _writer = mock_asyncio_connection

    t = AsyncRtuOverTcpTransport("host", port=1234)
    unit_id = 0x11

    # Build a complete exception response (5 bytes total: addr + func + exception + CRC)
    # Exception responses are exactly 5 bytes, same as MIN_RTU_RESPONSE_LENGTH + 1
    exception_pdu = b"\x83\x01"  # 0x03 + 0x80 = 0x83, exception code 1
    response_prefix = bytes([unit_id]) + exception_pdu
    crc = calculate_crc16(response_prefix)
    complete_frame = response_prefix + crc  # This is exactly 5 bytes

    # Mock readexactly to return the complete 5-byte frame in first read
    # Since MIN_RTU_RESPONSE_LENGTH is 4, we get 4 bytes initially
    # But for exception response, expected length is 5, so we need 1 more byte
    reader.readexactly = AsyncMock(
        side_effect=[
            complete_frame[:4],  # First read gets 4 bytes
            complete_frame[4:],  # Second read gets remaining 1 byte
        ]
    )

    t._reader = reader

    result = await t._receive_response()
    assert result == complete_frame


async def test_read_remaining_bytes_timeout(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test timeout when reading remaining bytes."""
    reader, _writer = mock_asyncio_connection

    # First call returns header, second call times out
    reader.readexactly = AsyncMock(
        side_effect=[
            b"\x01\x03\x02\x00",  # Header: unit 1, func 3, 2 bytes data
            asyncio.TimeoutError,  # Timeout on remaining bytes
        ]
    )

    t = AsyncRtuOverTcpTransport("host", port=1234)
    t._reader = reader

    with pytest.raises(asyncio.TimeoutError):
        await t._receive_response()


async def test_read_remaining_bytes_generic_exception(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test generic exception when reading remaining bytes."""
    reader, _writer = mock_asyncio_connection

    # First call returns header, second call raises generic exception
    reader.readexactly = AsyncMock(
        side_effect=[
            b"\x01\x03\x02\x00",  # Header: unit 1, func 3, 2 bytes data
            OSError("Connection error"),  # Generic exception
        ]
    )

    t = AsyncRtuOverTcpTransport("host", port=1234)
    t._reader = reader

    with pytest.raises(ModbusConnectionError, match="Failed to read remaining"):
        await t._receive_response()


async def test_writer_becomes_none_during_send(
    mock_asyncio_connection: tuple[MagicMock, MagicMock],
) -> None:
    """Test that send_and_receive raises error if writer becomes None during send."""
    reader, _writer = mock_asyncio_connection

    transport = AsyncRtuOverTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    unit_id = 0x11

    transport._reader = reader

    with (
        patch.object(transport, "is_open", MagicMock(return_value=True)),
        pytest.raises(ModbusConnectionError, match="Connection not established"),
    ):
        await transport.send_and_receive(unit_id, pdu)
