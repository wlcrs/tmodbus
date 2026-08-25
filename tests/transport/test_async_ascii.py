"""Tests for tmodbus/transport/async_ascii.py with Protocol-based architecture."""

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import serialx
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
    _PendingRequest,
    ascii_decode,
    ascii_encode,
    build_ascii_frame,
    decode_ascii_frame,
    validate_ascii_frame,
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


def test_decode_ascii_frame_valid() -> None:
    """Test decoding valid ASCII frame."""
    # Build a valid frame
    message = b"\x01\x03"
    lrc = calculate_lrc(message)
    hex_data = ascii_encode(message + bytes([lrc]))
    frame = b":" + hex_data + b"\r\n"

    raw = decode_ascii_frame(frame)
    assert raw[0] == 0x01  # address
    assert raw[1] == 0x03  # function code
    assert raw[-1] == lrc  # LRC
    assert validate_ascii_frame(raw)


def test_decode_ascii_frame_missing_start() -> None:
    """Test decoding frame without start marker."""
    with pytest.raises(ASCIIFrameError, match="does not start with ':'"):
        decode_ascii_frame(b"0103FC\r\n")


def test_decode_ascii_frame_missing_end() -> None:
    """Test decoding frame without end marker."""
    with pytest.raises(ASCIIFrameError, match="does not start with ':' and end with"):
        decode_ascii_frame(b":0103FC")


def test_decode_ascii_frame_invalid_hex() -> None:
    """Test decoding frame with invalid hex."""
    with pytest.raises(ASCIIFrameError, match="Invalid hex"):
        decode_ascii_frame(b":GGZZ\r\n")


def test_decode_ascii_frame_too_short() -> None:
    """Test decoding frame that's too short."""
    with pytest.raises(ASCIIFrameError, match="too short"):
        decode_ascii_frame(b":01\r\n")


def test_decode_ascii_frame_invalid_lrc_is_detectable() -> None:
    """Test that decode-only path keeps invalid LRC detectable."""
    # Valid structure but wrong LRC.
    raw = decode_ascii_frame(b":0103FF\r\n")
    assert not validate_ascii_frame(raw)


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
    """Fixture to mock serialx.create_serial_connection."""
    created_protocol: ModbusAsciiProtocol | None = None

    async def fake_create_serial_connection(
        _loop: Any, protocol_factory: Callable[[], ModbusAsciiProtocol], **_kwargs: Any
    ) -> tuple[asyncio.Transport, asyncio.Protocol]:
        nonlocal created_protocol
        created_protocol = protocol_factory()
        created_protocol.connection_made(mock_transport)
        return mock_transport, created_protocol

    monkeypatch.setattr(
        serialx,
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

    with patch.object(serialx, "create_serial_connection", fake_create_serial_connection):
        await t.open()
        assert t.is_open()

        # Open again should return early
        await t.open()
        assert t.is_open()


async def test_open_timeout_waiting_for_connection_made(monkeypatch: pytest.MonkeyPatch) -> None:
    """If connection_made never fires, open() times out and leaves no half-open transport."""
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False

    async def fake_create_serial_connection(
        _loop: Any, protocol_factory: Callable[[], ModbusAsciiProtocol], **_kwargs: Any
    ) -> tuple[asyncio.Transport, asyncio.Protocol]:
        # Return a transport/protocol but never call connection_made.
        return mock_transport, protocol_factory()

    monkeypatch.setattr(serialx, "create_serial_connection", fake_create_serial_connection)

    t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600, timeout=0.05)
    with pytest.raises(TimeoutError):
        await t.open()

    assert not t.is_open()
    mock_transport.close.assert_called_once()


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

    with patch.object(serialx, "create_serial_connection", timeout_connection):
        t = AsyncAsciiTransport("/dev/ttyUSB0", baudrate=9600, timeout=0.01)
        with pytest.raises(TimeoutError):
            await t.open()


async def test_open_connection_error() -> None:
    """Test connection error during open."""

    async def error_connection(*_args: Any, **_kwargs: Any) -> tuple[asyncio.Transport, asyncio.Protocol]:
        msg = "Connection failed"
        raise OSError(msg)

    with patch.object(serialx, "create_serial_connection", error_connection):
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

    # Send second request - should wait for gap.
    # Re-prime the gap timer so the remaining-gap assertion below does not
    # depend on real elapsed time since the response above.
    protocol._last_frame_ended_at = time.monotonic()
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
    """Test handling invalid frame (bad LRC) for pending request."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=10.0,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Send frame with bad LRC
    protocol.data_received(b":0103FF\r\n")  # Invalid LRC

    # Should fail fast because bad checksum matches pending unit_id.
    with pytest.raises(LRCError):
        await task


async def test_protocol_invalid_frame_wrong_unit_id_is_discarded(mock_transport: MagicMock) -> None:
    """Test bad-LRC frame for another unit does not fail the pending request."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.1,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Bad LRC frame for unit 2 while unit 1 is pending.
    protocol.data_received(b":0203FF\r\n")

    # Request for unit 1 should still timeout because frame is not attributable.
    with pytest.raises(TimeoutError):
        await task


async def test_protocol_invalid_hex_frame_is_discarded(mock_transport: MagicMock) -> None:
    """Test malformed ASCII frame (invalid hex) is logged and discarded."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.1,
    )
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    task = asyncio.create_task(protocol.send_and_receive(1, pdu))
    await asyncio.sleep(0.01)

    # Starts/ends like a frame but has invalid hex payload, exercising ASCIIFrameError path.
    protocol.data_received(b":GGZZ\r\n")

    # Request should still timeout because malformed frame is discarded.
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
    with pytest.raises(ModbusConnectionError, match="Not connected"):
        await task2
    with pytest.raises(ModbusConnectionError, match="Not connected"):
        await task3


async def test_protocol_multiple_frames(mock_transport: MagicMock) -> None:
    """Test receiving multiple frames in one data_received call."""
    protocol = ModbusAsciiProtocol(
        on_connection_lost=lambda _exc: None,
        timeout=0.05,
    )
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu1 = _DummyPDU()
    pdu1.function_code = 0x03

    pdu2 = _DummyPDU()
    pdu2.function_code = 0x06

    unit_id = 1

    # Request 1 times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)

    assert protocol._timed_out_requests[unit_id] is pdu1

    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    # Build delayed response for request 1 and valid response for request 2
    frame1 = build_ascii_frame(unit_id, b"\x03\x02\xaa\xbb")
    frame2 = build_ascii_frame(unit_id, b"\x06\x00\x01\x11\x22")

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    # Send both frames at once in single data_received call
    protocol.data_received(frame1 + frame2)

    res2 = await req2_task

    assert res2 == ("decoded", b"\x06\x00\x01\x11\x22")
    assert len(protocol._buffer) == 0


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


async def test_send_and_receive_timeout_resets_pending_request(
    mock_transport: MagicMock,
) -> None:
    """Test that send_and_receive resets _pending_request and stores timed-out PDU on timeout."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu = _DummyPDU()
    unit_id = 1

    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu)

    assert protocol._pending_request is None
    assert protocol._timed_out_requests[unit_id] is pdu


async def test_send_and_receive_serialized_by_bus_lock(
    mock_transport: MagicMock,
) -> None:
    """Test that concurrent send_and_receive calls are serialized by the bus lock."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=1.0)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu1 = _DummyPDU()
    pdu2 = _DummyPDU()
    unit_id_1 = 1
    unit_id_2 = 2

    resp1 = build_ascii_frame(unit_id_1, b"\x03\x02\x00\x0a")
    resp2 = build_ascii_frame(unit_id_2, b"\x03\x02\x00\x0b")

    async def deliver_responses() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(resp1)
        await asyncio.sleep(0.01)
        protocol.data_received(resp2)

    task1 = asyncio.create_task(protocol.send_and_receive(unit_id_1, pdu1))
    task2 = asyncio.create_task(protocol.send_and_receive(unit_id_2, pdu2))
    deliv_task = asyncio.create_task(deliver_responses())

    res1, res2 = await asyncio.gather(task1, task2)
    await deliv_task

    assert res1 == ("decoded", b"\x03\x02\x00\x0a")
    assert res2 == ("decoded", b"\x03\x02\x00\x0b")


async def test_delayed_response_after_timeout_is_cleanly_discarded(
    mock_transport: MagicMock,
) -> None:
    """Test that delayed response arriving after timeout is cleanly discarded using timed-out tracking."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu = _DummyPDU()
    unit_id = 1

    # Request times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu)

    assert protocol._timed_out_requests[unit_id] is pdu

    # Delayed response arrives
    delayed_frame = build_ascii_frame(unit_id, b"\x03\x02\x00\x55")
    protocol.data_received(delayed_frame)

    assert len(protocol._buffer) == 0
    assert unit_id not in protocol._timed_out_requests


async def test_delayed_response_during_active_request_same_unit(
    mock_transport: MagicMock,
) -> None:
    """Test that delayed response from timed-out request does not fail active request with different FC."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu1 = _DummyPDU()
    pdu1.function_code = 0x03

    pdu2 = _DummyPDU()
    pdu2.function_code = 0x06

    unit_id = 1

    # Step 1: Request 1 (FC 0x03) times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)

    assert protocol._timed_out_requests[unit_id] is pdu1

    # Step 2: Request 2 (FC 0x06) is sent and active
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    delayed_frame_1 = build_ascii_frame(unit_id, b"\x03\x02\xaa\xbb")
    real_frame_2 = build_ascii_frame(unit_id, b"\x06\x00\x01\x11\x22")

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    # Deliver late response for request 1
    protocol.data_received(delayed_frame_1)
    # Active request should still be pending and not failed
    assert protocol._pending_request is not None
    assert not protocol._pending_request.future.done()
    assert unit_id not in protocol._timed_out_requests

    # Deliver real response for request 2
    protocol.data_received(real_frame_2)

    result = await req2_task

    assert result == ("decoded", b"\x06\x00\x01\x11\x22")
    assert len(protocol._buffer) == 0


async def test_delayed_exception_response_during_active_request_same_unit(
    mock_transport: MagicMock,
) -> None:
    """Test that delayed exception response from timed-out request does not fail active request."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu1 = _DummyPDU()
    pdu1.function_code = 0x03

    pdu2 = _DummyPDU()
    pdu2.function_code = 0x06

    unit_id = 1

    # Step 1: Request 1 (FC 0x03) times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)

    assert protocol._timed_out_requests[unit_id] is pdu1

    # Step 2: Request 2 (FC 0x06) is sent and active
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    # Late exception response for Request 1 (FC 0x83, exception code 0x02)
    delayed_exc_frame_1 = build_ascii_frame(unit_id, b"\x83\x02")
    real_frame_2 = build_ascii_frame(unit_id, b"\x06\x00\x01\x11\x22")

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    # Deliver late exception response for request 1
    protocol.data_received(delayed_exc_frame_1)
    # Active request should still be pending and not failed
    assert protocol._pending_request is not None
    assert not protocol._pending_request.future.done()
    assert unit_id not in protocol._timed_out_requests

    # Deliver real response for request 2
    protocol.data_received(real_frame_2)

    result = await req2_task

    assert result == ("decoded", b"\x06\x00\x01\x11\x22")
    assert len(protocol._buffer) == 0


async def test_active_request_succeeds_and_clears_stale_timed_out_request(
    mock_transport: MagicMock,
) -> None:
    """Test that a successful response to an active request clears stale timed-out tracking."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu1 = _DummyPDU()
    pdu2 = _DummyPDU()
    unit_id = 1

    # Request 1 times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)

    assert protocol._timed_out_requests[unit_id] is pdu1

    # Request 2 is sent and succeeds
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    response = build_ascii_frame(unit_id, b"\x03\x02\x00\x55")

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    protocol.data_received(response)

    result = await req2_task

    assert result == ("decoded", b"\x03\x02\x00\x55")
    assert unit_id not in protocol._timed_out_requests


async def test_data_received_falls_back_to_pending_request_pdu_when_future_done(
    mock_transport: MagicMock,
) -> None:
    """Test that data_received uses _pending_request.pdu if future is done but _timed_out_requests not yet set."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    pdu.function_code = 0x03
    unit_id = 1

    # Simulate future cancelled/done by asyncio.wait_for timeout before send_and_receive cleans up
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
    fut.cancel()

    protocol._pending_request = _PendingRequest(unit_id=unit_id, future=fut, pdu=pdu)

    # Response arrives for the timed-out request
    response = build_ascii_frame(unit_id, b"\x03\x02\x00\x55")

    protocol.data_received(response)
    assert len(protocol._buffer) == 0


async def test_connection_lost_sets_exception_on_pending_request(
    mock_transport: MagicMock,
) -> None:
    """Test that connection_lost sets exception on pending request and clears state."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu = _DummyPDU()
    unit_id = 1

    async def lose_connection() -> None:
        await asyncio.sleep(0.05)
        protocol.connection_lost(None)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    connection_task = asyncio.create_task(lose_connection())

    with pytest.raises(ModbusConnectionError, match="Connection lost"):
        await result_task

    await connection_task
    assert protocol._pending_request is None
    assert len(protocol._timed_out_requests) == 0


async def test_cancelled_request_is_tracked_and_delayed_response_discarded(
    mock_transport: MagicMock,
) -> None:
    """A cancelled in-flight request is tracked so its delayed response is discarded cleanly."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=1.0)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu1 = _DummyPDU()
    unit_id = 1

    # Step 1: request is cancelled while in flight
    task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu1))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert protocol._pending_request is None
    assert protocol._timed_out_requests[unit_id] is pdu1

    # Step 2: the delayed response is discarded and clears the tracking
    delayed_frame = build_ascii_frame(unit_id, b"\x03\x02\x00\x55")
    protocol.data_received(delayed_frame)
    assert len(protocol._buffer) == 0
    assert unit_id not in protocol._timed_out_requests

    # Step 3: next request succeeds without stale interference
    pdu2 = _DummyPDU()
    response = build_ascii_frame(unit_id, b"\x03\x02\x00\x66")

    async def deliver_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response)

    task2 = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    deliv_task = asyncio.create_task(deliver_response())
    result = await task2
    await deliv_task

    assert result == ("decoded", b"\x03\x02\x00\x66")


async def test_corrupt_delayed_frame_keeps_timed_out_tracking(
    mock_transport: MagicMock,
) -> None:
    """A corrupted (bad LRC) frame must not clear the tracking for the real delayed response."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu = _DummyPDU()
    unit_id = 1

    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu)
    assert protocol._timed_out_requests[unit_id] is pdu

    good_frame = build_ascii_frame(unit_id, b"\x03\x02\x00\x55")
    corrupt_frame = good_frame.replace(b"0055", b"0056")  # data changed, LRC now invalid

    protocol.data_received(corrupt_frame)
    assert protocol._timed_out_requests[unit_id] is pdu  # tracking kept

    protocol.data_received(good_frame)
    assert unit_id not in protocol._timed_out_requests


async def test_corrupt_delayed_frame_during_active_request_keeps_tracking(
    mock_transport: MagicMock,
) -> None:
    """A corrupted delayed frame during an active request keeps tracking and the active request alive."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu1 = _DummyPDU()
    pdu1.function_code = 0x03

    pdu2 = _DummyPDU()
    pdu2.function_code = 0x06

    unit_id = 1

    # Step 1: Request 1 (FC 0x03) times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)
    assert protocol._timed_out_requests[unit_id] is pdu1

    # Step 2: Request 2 (FC 0x06) is sent and active
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    good_delayed_1 = build_ascii_frame(unit_id, b"\x03\x02\xaa\xbb")
    corrupt_delayed_1 = good_delayed_1.replace(b"AABB", b"AABC")  # data changed, LRC now invalid
    real_frame_2 = build_ascii_frame(unit_id, b"\x06\x00\x01\x11\x22")

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    # Corrupt delayed frame: discarded, tracking retained, active request unaffected
    protocol.data_received(corrupt_delayed_1)
    assert protocol._pending_request is not None
    assert not protocol._pending_request.future.done()
    assert protocol._timed_out_requests[unit_id] is pdu1

    # Real delayed frame clears the tracking
    protocol.data_received(good_delayed_1)
    assert unit_id not in protocol._timed_out_requests
    assert not protocol._pending_request.future.done()

    # Deliver real response for request 2
    protocol.data_received(real_frame_2)

    result = await req2_task

    assert result == ("decoded", b"\x06\x00\x01\x11\x22")
    assert len(protocol._buffer) == 0


async def test_lrc_error_on_active_request_keeps_timed_out_tracking(
    mock_transport: MagicMock,
) -> None:
    """An LRC failure on the active request's frame must not clear timed-out tracking."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=1.0)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    stale_pdu = _DummyPDU()
    unit_id = 1
    protocol._timed_out_requests[unit_id] = stale_pdu

    pdu = _DummyPDU()
    corrupt_frame = build_ascii_frame(unit_id, b"\x03\x02\x00\x55").replace(b"0055", b"0056")

    async def deliver_corrupt() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(corrupt_frame)

    task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    deliv_task = asyncio.create_task(deliver_corrupt())
    with pytest.raises(LRCError):
        await task
    await deliv_task

    assert protocol._timed_out_requests[unit_id] is stale_pdu


async def test_timeout_does_not_log_error(
    mock_transport: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A response timeout is routine: no ERROR-level logging, matching RTU."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    with (
        caplog.at_level(logging.ERROR, logger="tmodbus.transport.async_ascii"),
        pytest.raises(TimeoutError),
    ):
        await protocol.send_and_receive(1, _DummyPDU())

    assert not caplog.records


async def test_send_and_receive_no_response_pdu(
    mock_transport: MagicMock,
) -> None:
    """Test send_and_receive when PDU expects_response is False."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    class NoResponsePDU(BaseClientPDU[None]):
        function_code = 0x08
        expects_response = False

        def encode_request(self) -> bytes:
            return b"\x00\x04\x00\x00"

        def decode_response(self, _response: bytes) -> None:
            return None

    await protocol.send_and_receive(1, NoResponsePDU())
