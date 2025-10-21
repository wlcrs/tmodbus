"""Tests for tmodbus/transport/async_ascii.py with Protocol-based architecture."""

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import serial_asyncio_fast
from tmodbus.exceptions import (
    ASCIIFrameError,
    IllegalFunctionError,
    InvalidResponseError,
    LRCError,
    ModbusConnectionError,
)
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_ascii import (
    ASCII_FRAME_END,
    ASCII_FRAME_START,
    MAX_ASCII_FRAME_SIZE,
    AsyncAsciiTransport,
    ModbusAsciiProtocol,
    _ModbusAsciiMessage,
    ascii_decode,
    ascii_encode,
    build_ascii_frame,
    parse_ascii_frame,
)
from tmodbus.utils.lrc import calculate_lrc


# Test helper functions
def test_ascii_encode() -> None:
    """Test ASCII hex encoding."""
    assert ascii_encode(b"\x01\x03") == b"0103"
    assert ascii_encode(b"\xab\xcd\xef") == b"ABCDEF"
    assert ascii_encode(b"\x00") == b"00"
    assert ascii_encode(b"\xff") == b"FF"


def test_ascii_decode() -> None:
    """Test ASCII hex decoding."""
    assert ascii_decode(b"0103") == b"\x01\x03"
    assert ascii_decode(b"ABCDEF") == b"\xab\xcd\xef"
    assert ascii_decode(b"abcdef") == b"\xab\xcd\xef"  # lowercase works too
    assert ascii_decode(b"00") == b"\x00"
    assert ascii_decode(b"FF") == b"\xff"


def test_ascii_encode_decode_roundtrip() -> None:
    """Test encoding and decoding roundtrip."""
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
    """Test building minimal frame."""
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


def test_parse_ascii_frame_valid() -> None:
    """Test parsing valid ASCII frame."""
    # Build a valid frame
    message = b"\x01\x03"
    lrc = calculate_lrc(message)
    hex_data = ascii_encode(message + bytes([lrc]))
    frame = b":" + hex_data + b"\r\n"

    raw = parse_ascii_frame(frame)
    assert raw[0] == 0x01  # address
    assert raw[1] == 0x03  # function code
    assert raw[-1] == lrc  # LRC


def test_parse_ascii_frame_missing_start() -> None:
    """Test parsing frame without start marker."""
    with pytest.raises(ASCIIFrameError, match="does not start with ':'"):
        parse_ascii_frame(b"0103FC\r\n")


def test_parse_ascii_frame_missing_end() -> None:
    """Test parsing frame without end marker."""
    with pytest.raises(ASCIIFrameError, match="does not start with ':' and end with"):
        parse_ascii_frame(b":0103FC")


def test_parse_ascii_frame_invalid_hex() -> None:
    """Test parsing frame with invalid hex."""
    with pytest.raises(ASCIIFrameError, match="Invalid hex"):
        parse_ascii_frame(b":GGZZ\r\n")


def test_parse_ascii_frame_too_short() -> None:
    """Test parsing frame that's too short."""
    with pytest.raises(ASCIIFrameError, match="too short"):
        parse_ascii_frame(b":01\r\n")


def test_parse_ascii_frame_invalid_lrc() -> None:
    """Test parsing frame with invalid LRC."""
    # Valid structure but wrong LRC
    with pytest.raises(LRCError):
        parse_ascii_frame(b":0103FF\r\n")  # FF is wrong LRC


# Fixtures
class _DummyPDU(BaseClientPDU[tuple[str, bytes]]):
    function_code = 0x03

    def encode_request(self) -> bytes:
        return b"\x00\x00\x00\x01"

    def decode_response(self, data: bytes) -> tuple[str, bytes]:
        return ("decoded", data)


@pytest.fixture
def mock_transport() -> MagicMock:
    """Fixture to create a mock transport."""
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    return mock_transport


@pytest.fixture
def mock_serial_connection(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MagicMock, Callable[[], ModbusAsciiProtocol | None]]:
    """Fixture to mock serial_asyncio_fast.create_serial_connection."""
    created_protocol: ModbusAsciiProtocol | None = None

    async def fake_create_serial_connection(
        _loop: Any, protocol_factory: Callable[[], ModbusAsciiProtocol], **_kwargs: Any
    ) -> tuple[asyncio.Transport, asyncio.Protocol]:
        nonlocal created_protocol
        created_protocol = protocol_factory()
        created_protocol.connection_made(mock_transport)
        return mock_transport, created_protocol

    monkeypatch.setattr(
        serial_asyncio_fast,
        "create_serial_connection",
        fake_create_serial_connection,
    )

    return mock_transport, lambda: created_protocol


# AsyncAsciiTransport tests
async def test_open_already_open() -> None:
    """Test that open early-returns if already open."""
    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False

    async def fake_create_serial_connection(
        _loop: Any, protocol_factory: Any, **_kwargs: Any
    ) -> tuple[asyncio.Transport, asyncio.Protocol]:
        protocol = protocol_factory()
        protocol.connection_made(mock_transport)
        return mock_transport, protocol

    with patch.object(serial_asyncio_fast, "create_serial_connection", fake_create_serial_connection):
        await t.open()
        assert t.is_open()

        # Open again should return early
        await t.open()
        assert t.is_open()


async def test_open_and_close(
    mock_serial_connection: tuple[MagicMock, Callable[[], ModbusAsciiProtocol | None]],
) -> None:
    """Test opening and closing connection."""
    _mock_transport, get_protocol = mock_serial_connection

    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    assert not t.is_open()

    await t.open()
    assert t.is_open()
    protocol = get_protocol()
    assert protocol is not None

    await t.close()


async def test_open_timeout() -> None:
    """Test connection timeout during open."""

    async def timeout_connection(*_args: Any, **_kwargs: Any) -> tuple[asyncio.Transport, asyncio.Protocol]:
        await asyncio.sleep(100)  # Will timeout
        msg = "Should not reach here"
        raise AssertionError(msg)  # pragma: no cover

    with patch.object(serial_asyncio_fast, "create_serial_connection", timeout_connection):
        t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600, timeout=0.01)
        with pytest.raises(TimeoutError):
            await t.open()


async def test_open_connection_error() -> None:
    """Test connection error during open."""

    async def error_connection(*_args: Any, **_kwargs: Any) -> tuple[asyncio.Transport, asyncio.Protocol]:
        msg = "Connection failed"
        raise OSError(msg)

    with patch.object(serial_asyncio_fast, "create_serial_connection", error_connection):
        t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
        with pytest.raises(ModbusConnectionError):
            await t.open()


async def test_close_already_closed() -> None:
    """Test closing already closed connection."""
    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    # Should not raise
    await t.close()


async def test_close_when_closing(
    mock_serial_connection: tuple[MagicMock, Callable[[], ModbusAsciiProtocol | None]],
) -> None:
    """Test closing when transport is already closing."""
    mock_transport, _get_protocol = mock_serial_connection

    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()

    # Mark as closing
    mock_transport.is_closing.return_value = True
    # Should not call close on transport
    await t.close()
    mock_transport.close.assert_not_called()


async def test_is_open_states(
    mock_serial_connection: tuple[MagicMock, Callable[[], ModbusAsciiProtocol | None]],
) -> None:
    """Test is_open in various states."""
    mock_transport, _get_protocol = mock_serial_connection

    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    assert not t.is_open()

    await t.open()
    assert t.is_open()

    mock_transport.is_closing.return_value = True
    assert not t.is_open()


async def test_send_and_receive_not_connected() -> None:
    """Test send_and_receive when not connected."""
    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    pdu = _DummyPDU()

    with pytest.raises(ModbusConnectionError, match="not connected"):
        await t.send_and_receive(1, pdu)


async def test_send_and_receive_protocol_none(
    mock_serial_connection: tuple[MagicMock, Callable[[], ModbusAsciiProtocol | None]],
) -> None:
    """Test send_and_receive when protocol is None."""
    _mock_transport, _get_protocol = mock_serial_connection

    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()

    # Manually set protocol to None
    t._protocol = None
    pdu = _DummyPDU()

    with pytest.raises(ModbusConnectionError, match="not connected"):
        await t.send_and_receive(1, pdu)


async def test_connection_lost_callback(
    mock_serial_connection: tuple[MagicMock, Callable[[], ModbusAsciiProtocol | None]],
) -> None:
    """Test connection lost callback."""
    _mock_transport, get_protocol = mock_serial_connection

    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()
    protocol = get_protocol()

    assert t._transport is not None
    assert t._protocol is not None
    assert protocol is not None

    # Simulate connection lost
    protocol.connection_lost(ConnectionResetError("Connection reset"))

    assert t._transport is None
    assert t._protocol is None


# ModbusAsciiProtocol tests
async def test_protocol_connection_made(mock_transport: MagicMock) -> None:
    """Test protocol connection_made event."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )

    assert not protocol.connection_made_event.is_set()
    protocol.connection_made(mock_transport)
    assert protocol.connection_made_event.is_set()
    assert protocol.transport == mock_transport


async def test_protocol_send_receive_success(mock_transport: MagicMock) -> None:
    """Test successful send and receive."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start send_and_receive in background
    task = asyncio.create_task(protocol.send_and_receive(1, pdu))

    # Give it time to send
    await asyncio.sleep(0.01)

    # Verify write was called
    assert mock_transport.write.called
    sent_data = mock_transport.write.call_args[0][0]
    assert sent_data.startswith(b":")
    assert sent_data.endswith(b"\r\n")

    # Simulate response
    # Build response: address 01, function 03, data 02 bytes (00 00)
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"

    protocol.data_received(response_frame)

    # Wait for result
    result = await task
    assert result == ("decoded", response_pdu)


async def test_protocol_send_receive_timeout(mock_transport: MagicMock) -> None:
    """Test send and receive timeout."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.05,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    with pytest.raises(TimeoutError, match="timeout"):
        await protocol.send_and_receive(1, pdu)


async def test_protocol_exception_response(mock_transport: MagicMock) -> None:
    """Test handling exception response."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Exception response: function code | 0x80, exception code 01
    exception_pdu = b"\x83\x01"  # 0x03 | 0x80 = 0x83, exception code 01
    response_message = bytes([1]) + exception_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"

    protocol.data_received(response_frame)

    with pytest.raises(IllegalFunctionError):
        await task


async def test_protocol_function_code_mismatch(mock_transport: MagicMock) -> None:
    """Test handling function code mismatch."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # function code 03

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Response with wrong function code 04
    response_pdu = b"\x04\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"

    protocol.data_received(response_frame)

    with pytest.raises(InvalidResponseError, match="Function code mismatch"):
        await task


async def test_protocol_interframe_gap(mock_transport: MagicMock) -> None:
    """Test inter-frame gap enforcement."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _: None,
        timeout=10.0,
        interframe_gap=0.05,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Send first request
    task1 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Respond immediately
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"
    protocol.data_received(response_frame)
    await task1

    # Send second request - should wait for gap
    orig_sleep = asyncio.sleep
    with patch("asyncio.sleep", wraps=asyncio.sleep) as mock_sleep:
        asyncio.create_task(protocol.send_and_receive(1, pdu))  # noqa: RUF006

        await orig_sleep(0.01)
        mock_sleep.assert_awaited_once()

        assert mock_sleep.call_args[0][0] > 0.01


async def test_protocol_garbage_data(mock_transport: MagicMock) -> None:
    """Test handling garbage data before frame."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Send garbage then valid frame
    protocol.data_received(b"garbage_data")

    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"

    protocol.data_received(response_frame)

    result = await task
    assert result == ("decoded", response_pdu)


async def test_protocol_partial_frame(mock_transport: MagicMock) -> None:
    """Test handling partial frame reception."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Send frame in parts
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"

    # Send first half
    mid = len(response_frame) // 2
    protocol.data_received(response_frame[:mid])
    await asyncio.sleep(0.01)

    # Send second half
    protocol.data_received(response_frame[mid:])

    result = await task
    assert result == ("decoded", response_pdu)


async def test_protocol_invalid_frame(mock_transport: MagicMock) -> None:
    """Test handling invalid frame (bad LRC)."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.1,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Send frame with bad LRC
    protocol.data_received(b":0103FF\r\n")  # Invalid LRC

    # Should timeout because frame was discarded
    with pytest.raises(TimeoutError):
        await task


async def test_protocol_oversized_frame(mock_transport: MagicMock) -> None:
    """Test handling oversized frame."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.1,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Send oversized buffer (no end marker)
    huge_data = b":" + b"A" * (MAX_ASCII_FRAME_SIZE + 100)
    protocol.data_received(huge_data)

    # Should timeout because buffer was cleared
    with pytest.raises(TimeoutError):
        await task


async def test_protocol_wrong_unit_id(mock_transport: MagicMock) -> None:
    """Test receiving frame for wrong unit ID."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.1,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Request for unit 1
    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Response for unit 2
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([2]) + response_pdu  # Wrong unit ID
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"

    protocol.data_received(response_frame)

    # Should timeout because wrong unit
    with pytest.raises(TimeoutError):
        await task


async def test_protocol_connection_lost_with_pending(mock_transport: MagicMock) -> None:
    """Test connection lost with pending requests."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Simulate connection lost
    protocol.connection_lost(ConnectionResetError("Connection reset"))

    with pytest.raises(ModbusConnectionError, match="Connection lost"):
        await task


async def test_protocol_connection_lost_with_multiple_pending(mock_transport: MagicMock) -> None:
    """Test connection lost with multiple pending requests to cover loop iteration."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Create multiple pending requests for different unit IDs
    task1 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)
    task2 = asyncio.create_task(protocol.send_and_receive(2, pdu))
    await asyncio.sleep(0.01)
    task3 = asyncio.create_task(protocol.send_and_receive(3, pdu))
    await asyncio.sleep(0.01)

    # Simulate connection lost - this should iterate over all pending requests
    protocol.connection_lost(ConnectionResetError("Connection reset"))

    # All tasks should raise ModbusConnectionError
    with pytest.raises(ModbusConnectionError, match="Connection lost"):
        await task1
    with pytest.raises(ModbusConnectionError, match="Connection lost"):
        await task2
    with pytest.raises(ModbusConnectionError, match="Connection lost"):
        await task3


async def test_protocol_multiple_frames(mock_transport: MagicMock) -> None:
    """Test receiving multiple frames in one data_received call."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start two requests for different units
    task1 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    task2 = asyncio.create_task(protocol.send_and_receive(2, pdu))
    await asyncio.sleep(0.01)

    # Build two responses
    response_pdu = b"\x03\x02\x00\x00"

    response1_message = bytes([1]) + response_pdu
    lrc1 = calculate_lrc(response1_message)
    frame1 = b":" + ascii_encode(response1_message + bytes([lrc1])) + b"\r\n"

    response2_message = bytes([2]) + response_pdu
    lrc2 = calculate_lrc(response2_message)
    frame2 = b":" + ascii_encode(response2_message + bytes([lrc2])) + b"\r\n"

    # Send both frames at once
    protocol.data_received(frame1 + frame2)

    result1 = await task1
    result2 = await task2

    assert result1 == ("decoded", response_pdu)
    assert result2 == ("decoded", response_pdu)


async def test_protocol_send_not_connected() -> None:
    """Test send_and_receive when transport is not connected."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    # Don't call connection_made, so transport is None

    pdu = _DummyPDU()

    with pytest.raises(ModbusConnectionError, match="Not connected"):
        await protocol.send_and_receive(1, pdu)


async def test_protocol_send_when_closing(mock_transport: MagicMock) -> None:
    """Test send_and_receive when transport is closing."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    # Mark as closing
    mock_transport.is_closing.return_value = True

    pdu = _DummyPDU()

    with pytest.raises(ModbusConnectionError, match="Not connected"):
        await protocol.send_and_receive(1, pdu)


async def test_protocol_sequential_requests_same_unit(mock_transport: MagicMock) -> None:
    """Test sequential requests to same unit wait for previous to complete."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start first request
    task1 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Start second request to same unit (should wait)
    task2 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Respond to first
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"

    protocol.data_received(response_frame)
    await task1

    # Now respond to second
    protocol.data_received(response_frame)
    await task2


async def test_integration_full_workflow(
    mock_serial_connection: tuple[MagicMock, Callable[[], ModbusAsciiProtocol | None]],
) -> None:
    """Test complete workflow: open, send/receive, close."""
    _mock_transport, get_protocol = mock_serial_connection

    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)

    # Open
    await t.open()
    assert t.is_open()
    protocol = get_protocol()

    assert protocol is not None

    # Send and receive
    pdu = _DummyPDU()
    task = asyncio.create_task(t.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Simulate response
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"

    protocol.data_received(response_frame)
    result = await task
    assert result == ("decoded", response_pdu)

    # Close
    await t.close()


async def test_protocol_connection_made_wrong_type() -> None:
    """Test protocol connection_made with wrong transport type."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )

    # Use a BaseTransport instead of WriteTransport
    bad_transport = MagicMock(spec=asyncio.BaseTransport)

    with pytest.raises(TypeError, match="Expected a WriteTransport"):
        protocol.connection_made(bad_transport)


async def test_protocol_previous_request_timeout(mock_transport: MagicMock) -> None:
    """Test waiting for previous request that times out."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.2,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start first request (will timeout)
    task1 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)  # Let first request get started

    # Start second request to same unit WHILE first is still pending
    task2 = asyncio.create_task(protocol.send_and_receive(1, pdu))

    # Wait for first to timeout
    with pytest.raises(TimeoutError):
        await task1

    # Second should proceed after waiting for first to timeout, respond to it
    await asyncio.sleep(0.01)
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"
    protocol.data_received(response_frame)

    result = await task2
    assert result == ("decoded", response_pdu)


async def test_protocol_previous_request_exception(mock_transport: MagicMock) -> None:
    """Test waiting for previous request that raises exception."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start first request
    task1 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Start second request to same unit WHILE first is still pending
    task2 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Send exception response to first
    exception_pdu = b"\x83\x01"  # Exception response
    response_message = bytes([1]) + exception_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"
    protocol.data_received(response_frame)

    # First should raise exception
    with pytest.raises(IllegalFunctionError):
        await task1

    # Second should proceed after waiting for first to fail, respond to it
    await asyncio.sleep(0.01)

    # Send normal response to second
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"
    protocol.data_received(response_frame)

    result = await task2
    assert result == ("decoded", response_pdu)


async def test_protocol_previous_request_success(mock_transport: MagicMock) -> None:
    """Test waiting for previous request that succeeds."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start first request
    task1 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Start second request to same unit WHILE first is still pending
    task2 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Send response to first
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"
    protocol.data_received(response_frame)

    await task1

    # Second should proceed after waiting for first to finish
    await asyncio.sleep(0.01)

    # Send response to second
    protocol.data_received(response_frame)

    result = await task2
    assert result == ("decoded", response_pdu)


async def test_protocol_previous_request_cancelled(mock_transport: MagicMock) -> None:
    """Test waiting for previous request that gets cancelled."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start first request
    task1 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Start second request to same unit WHILE first is still pending
    # This should trigger the wait logic and hit the CancelledError handler
    task2 = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Cancel the first request
    task1.cancel()

    # Wait for first to be cancelled
    with pytest.raises(asyncio.CancelledError):
        await task1

    # Second should proceed after catching CancelledError from waiting for first
    await asyncio.sleep(0.01)

    # Send response to second
    response_pdu = b"\x03\x02\x00\x00"
    response_message = bytes([1]) + response_pdu
    lrc = calculate_lrc(response_message)
    response_frame = b":" + ascii_encode(response_message + bytes([lrc])) + b"\r\n"
    protocol.data_received(response_frame)

    result = await task2
    assert result == ("decoded", response_pdu)


async def test_protocol_discard_garbage_no_start_marker(mock_transport: MagicMock) -> None:
    """Test _discard_garbage_data when no start marker is found."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.1,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Send data with no start marker at all
    protocol.data_received(b"GARBAGE_NO_COLON_HERE\r\n")

    # Buffer should be cleared, request should timeout
    with pytest.raises(TimeoutError):
        await task


async def test_protocol_discard_garbage_start_marker_in_middle(caplog: pytest.LogCaptureFixture) -> None:
    """Test _discard_garbage_data when start marker is in the middle."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol._buffer = bytearray(b"GARBAGE_BEFORE_COLON:VALIDDATA\r\n")
    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_ascii"):
        protocol._discard_garbage_data()
        assert caplog.records[0].message.startswith("Discarding")
    assert protocol._buffer == bytearray(b":VALIDDATA\r\n")


async def test_protocol_discard_garbage_start_marker_at_start() -> None:
    """Test _discard_garbage_data when start marker is at the beginning."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol._buffer = bytearray(b":VALIDDATA\r\n")
    protocol._discard_garbage_data()

    assert protocol._buffer == bytearray(b":VALIDDATA\r\n")


async def test_protocol_discard_garbage_empty_buffer(mock_transport: MagicMock) -> None:
    """Test _discard_garbage_data when buffer is empty."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.1,
    )
    protocol.connection_made(mock_transport)

    # Manually call _discard_garbage_data with empty buffer
    # This should hit the path where start_pos == -1 but len(buffer) == 0
    protocol._discard_garbage_data()  # Should return without doing anything
    assert len(protocol._buffer) == 0


async def test_close_with_exception(
    mock_serial_connection: tuple[MagicMock, Callable[[], ModbusAsciiProtocol | None]],
) -> None:
    """Test close handling exceptions from transport.close()."""
    mock_transport, _get_protocol = mock_serial_connection

    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()

    # Make close() raise an exception
    msg = "Close error"
    mock_transport.close.side_effect = RuntimeError(msg)

    # Should not raise, just log
    await t.close()


async def test_connection_lost_without_exception(
    mock_serial_connection: tuple[MagicMock, Callable[[], ModbusAsciiProtocol | None]],
) -> None:
    """Test connection lost callback without exception."""
    _mock_transport, get_protocol = mock_serial_connection

    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()
    protocol = get_protocol()
    assert protocol is not None

    # Simulate clean connection close (no exception)
    protocol.connection_lost(None)

    assert t._transport is None
    assert t._protocol is None


async def test_wait_on_pending_request_no_pending() -> None:
    """Test _wait_on_pending_request when there's no pending request for the unit_id."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None)

    # Should return immediately when there's no pending request
    await protocol._wait_on_pending_request(1)
    # If we get here without blocking, the test passes


async def test_wait_on_pending_request_already_done() -> None:
    """Test _wait_on_pending_request when pending request is already done."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None)

    # Create a future that's already done
    done_future: asyncio.Future[_ModbusAsciiMessage] = asyncio.get_event_loop().create_future()
    done_future.set_result(_ModbusAsciiMessage(unit_id=1, pdu_bytes=b"\x03\x00", lrc=b"\x00\x00"))
    protocol._pending_requests[1] = done_future

    # Should return immediately when future is already done
    await protocol._wait_on_pending_request(1)
    # If we get here without blocking, the test passes


async def test_wait_on_pending_request_waits_for_completion(caplog: pytest.LogCaptureFixture) -> None:
    """Test _wait_on_pending_request waits for pending request to complete successfully."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=1.0)

    # Create a pending future
    pending_future: asyncio.Future[_ModbusAsciiMessage] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = pending_future

    # Set up a task to complete the future after a delay
    async def complete_future() -> None:
        await asyncio.sleep(0.05)
        pending_future.set_result(_ModbusAsciiMessage(unit_id=1, pdu_bytes=b"\x03\x00", lrc=b"\x00\x00"))

    complete_task = asyncio.create_task(complete_future())

    # Should wait for the future to complete
    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_ascii"):
        await protocol._wait_on_pending_request(1)

        # Should have logged success
        assert any("succeeded" in record.message for record in caplog.records)

    await complete_task


async def test_wait_on_pending_request_cancelled(caplog: pytest.LogCaptureFixture) -> None:
    """Test _wait_on_pending_request when pending request is cancelled."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=1.0)

    # Create a pending future
    pending_future: asyncio.Future[_ModbusAsciiMessage] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = pending_future

    # Set up a task to cancel the future after a delay
    async def cancel_future() -> None:
        await asyncio.sleep(0.05)
        pending_future.cancel()

    cancel_task = asyncio.create_task(cancel_future())

    # Should wait for the future and handle cancellation
    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_ascii"):
        await protocol._wait_on_pending_request(1)

        # Should have logged cancellation
        assert any("cancelled" in record.message for record in caplog.records)

    await cancel_task


async def test_wait_on_pending_request_generic_exception(caplog: pytest.LogCaptureFixture) -> None:
    """Test _wait_on_pending_request when pending request raises a generic exception."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=1.0)

    # Create a pending future
    pending_future: asyncio.Future[_ModbusAsciiMessage] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = pending_future

    # Set up a task to fail the future after a delay
    async def fail_future() -> None:
        await asyncio.sleep(0.05)
        pending_future.set_exception(RuntimeError("Previous request error"))

    fail_task = asyncio.create_task(fail_future())

    # Should wait for the future and handle the exception
    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_ascii"):
        await protocol._wait_on_pending_request(1)

        # Should have logged the failure
        assert any("failed" in record.message for record in caplog.records)

    await fail_task


async def test_wait_on_pending_request_timeout_waiting(caplog: pytest.LogCaptureFixture) -> None:
    """Test _wait_on_pending_request when waiting times out."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=0.1)

    # Create a pending future that never completes
    pending_future: asyncio.Future[_ModbusAsciiMessage] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = pending_future

    # Should timeout and log it
    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_ascii"):
        await protocol._wait_on_pending_request(1)

        # Should have logged timeout
        assert any("timed out" in record.message for record in caplog.records)


async def test_connection_lost_dont_set_exception_on_done_requests(
    mock_transport: MagicMock,
) -> None:
    """Test that connection_lost sets exception on all pending requests."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu = _DummyPDU()
    unit_id = 1

    # add a future that is already done to _pending_requests to test that it is skipped
    done_future = asyncio.get_event_loop().create_future()
    done_future.set_result(None)
    protocol._pending_requests[2] = done_future

    async def lose_connection() -> None:
        await asyncio.sleep(0.05)
        protocol.connection_lost(None)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    connection_task = asyncio.create_task(lose_connection())

    with pytest.raises(ModbusConnectionError, match="Connection lost"):
        await result_task

    await connection_task
