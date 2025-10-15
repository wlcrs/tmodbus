"""Tests for tmodbus/transport/async_tcp.py with Protocol-based implementation."""

import asyncio
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tmodbus.exceptions import InvalidResponseError, ModbusConnectionError, ModbusResponseError
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_tcp import AsyncTcpTransport, ModbusTcpProtocol, _ModbusMessage


class _DummyPDU(BaseClientPDU[tuple[str, bytes]]):
    function_code = 0x03

    def encode_request(self) -> bytes:
        return b"\x03\x04"

    def decode_response(self, data: bytes) -> tuple[str, bytes]:
        return ("decoded", data)


async def test_invalid_constructor_args() -> None:
    """Test that invalid constructor arguments raise ValueError."""
    with pytest.raises(ValueError, match=r"Port must be .*"):
        AsyncTcpTransport("host", port=0)
    with pytest.raises(ValueError, match=r"Timeout must .*"):
        AsyncTcpTransport("host", timeout=0)
    with pytest.raises(ValueError, match=r"Connect timeout must .*"):
        AsyncTcpTransport("host", connect_timeout=0)


async def test_open_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that connection errors during open are handled."""

    async def mock_create_connection(*_args: object, **_kwargs: object) -> tuple[None, None]:
        msg = "Connection failed"
        raise RuntimeError(msg)

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_connection", mock_create_connection)

    t = AsyncTcpTransport("host", port=1234)
    with pytest.raises(ModbusConnectionError):
        await t.open()


async def test_is_open_false_when_not_connected() -> None:
    """Test is_open returns False when not connected."""
    t = AsyncTcpTransport("host", port=1234)
    assert not t.is_open()


async def test_send_and_receive_not_connected() -> None:
    """Test that sending when not connected raises ModbusConnectionError."""
    t = AsyncTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    with pytest.raises(ModbusConnectionError):
        await t.send_and_receive(1, pdu)


async def test_close_already_closed() -> None:
    """Test that closing an already closed transport logs and returns early."""
    t = AsyncTcpTransport("host", port=1234)
    # Should early return and log if already closed
    with patch("tmodbus.transport.async_tcp.logger") as log:
        await t.close()
        log.debug.assert_called()


async def test_open_other_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that exceptions during open are logged and re-raised as ModbusConnectionError."""

    async def mock_create_connection(*_args: object, **_kwargs: object) -> tuple[None, None]:
        msg = "fail"
        raise RuntimeError(msg)

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_connection", mock_create_connection)

    t = AsyncTcpTransport("host", port=1234)
    with patch("tmodbus.transport.async_tcp.logger") as log:
        with pytest.raises(ModbusConnectionError):
            await t.open()
        log.exception.assert_called()


async def test_close_during_send_and_receive() -> None:
    """Test that a ModbusConnectionError is raised if the connection is closed during send_and_receive."""
    t = AsyncTcpTransport("host", port=1234)
    t._protocol = None
    with patch.object(t, "is_open", return_value=True):
        pdu = _DummyPDU()
        with pytest.raises(ModbusConnectionError):
            await t.send_and_receive(1, pdu)


async def test_is_open_with_transport() -> None:
    """Test is_open returns True when transport is connected."""
    t = AsyncTcpTransport("host", port=1234)
    # Create mock transport
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    t._transport = mock_transport

    assert t.is_open()


async def test_is_open_with_closing_transport() -> None:
    """Test is_open returns False when transport is closing."""
    t = AsyncTcpTransport("host", port=1234)
    # Create mock transport
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = True
    t._transport = mock_transport

    assert not t.is_open()


async def test_protocol_transaction_id_wraparound() -> None:
    """Test that Transaction ID wraps around after reaching 0xFFFF."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)

    protocol._next_transaction_id = 0xFFFF
    tid1 = await protocol._get_next_transaction_id()
    tid2 = await protocol._get_next_transaction_id()
    assert tid1 == 0xFFFF
    assert tid2 == 0


async def test_protocol_connection_made() -> None:
    """Test that connection_made is called correctly."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)

    protocol.connection_made(mock_transport)

    assert protocol.transport == mock_transport


async def test_protocol_connection_made_invalid_transport() -> None:
    """Test that connection_made is called with an invalid transport."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock()

    with pytest.raises(TypeError):
        protocol.connection_made(mock_transport)


async def test_protocol_data_received_complete_frame() -> None:
    """Test protocol handles receiving a complete Modbus response frame."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    protocol.connection_made(mock_transport)

    # Create a pending request
    future: asyncio.Future[_ModbusMessage] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = future

    # MBAP header: tid=1, pid=0, len=3, uid=1 + PDU: 0x03 0x04
    response_data = b"\x00\x01\x00\x00\x00\x03\x01\x03\x04"

    protocol.data_received(response_data)

    # Wait a bit for processing
    await asyncio.sleep(0.01)

    assert future.done()
    result = future.result()
    assert hasattr(result, "transaction_id")
    assert result.transaction_id == 1


async def test_protocol_data_received_unexpected_transaction_id() -> None:
    """Test protocol handles unexpected transaction ID gracefully."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    protocol.connection_made(mock_transport)

    # MBAP header: tid=99 (not in pending_requests), pid=0, len=3, uid=1
    response_data = b"\x00\x63\x00\x00\x00\x03\x01\x03\x04"

    with patch("tmodbus.transport.async_tcp.logger") as log:
        protocol.data_received(response_data)
        await asyncio.sleep(0.01)
        log.warning.assert_called()


async def test_protocol_connection_lost() -> None:
    """Test that connection_lost callback is invoked."""
    callback_called = False
    exception = None

    def on_lost(exc: Exception | None) -> None:
        nonlocal callback_called, exception
        callback_called = True
        exception = exc

    protocol = ModbusTcpProtocol(on_connection_lost=on_lost, timeout=10.0)

    test_exception = RuntimeError("Connection lost")
    protocol.connection_lost(test_exception)

    assert callback_called
    assert exception == test_exception


async def test_protocol_send_and_receive_not_connected() -> None:
    """Test send_and_receive raises error when not connected."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    pdu = _DummyPDU()

    with pytest.raises(ModbusConnectionError, match="Not connected"):
        await protocol.send_and_receive(1, pdu)


async def test_protocol_send_and_receive_exception_response() -> None:
    """Test protocol handles exception response correctly."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start send_and_receive in the background
    task = asyncio.create_task(protocol.send_and_receive(1, pdu))

    # Give it time to setup
    await asyncio.sleep(0.01)

    # Simulate receiving an exception response
    # MBAP: tid=1, pid=0, len=3, uid=1 + Exception PDU: 0x83 (0x03|0x80), code=0x01
    response_data = b"\x00\x01\x00\x00\x00\x03\x01\x83\x01"
    protocol.data_received(response_data)

    # Should raise ModbusResponseError
    with pytest.raises(ModbusResponseError):
        await task


async def test_protocol_send_and_receive_timeout() -> None:
    """Test protocol handles timeout correctly."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=0.1)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Should timeout since no response is sent
    with pytest.raises(TimeoutError, match="Response timeout"):
        await protocol.send_and_receive(1, pdu)


async def test_protocol_send_and_receive_invalid_protocol_id(caplog: pytest.LogCaptureFixture) -> None:
    """Test protocol validates protocol ID."""
    caplog.set_level("DEBUG", logger="tmodbus.transport.async_tcp")
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=0.02)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start send_and_receive in the background
    task = asyncio.create_task(protocol.send_and_receive(1, pdu))

    # Give it time to setup
    await asyncio.sleep(0.01)

    # MBAP: tid=1, pid=1 (invalid!), len=3, uid=1
    response_data = b"\x00\x01\x00\x01\x00\x03\x01\x03\x04"
    protocol.data_received(response_data)
    # Should log "garbage bytes" at debug level
    with pytest.raises(TimeoutError):
        await task

    assert any("garbage bytes" in record.message for record in caplog.records)


async def test_protocol_send_and_receive_invalid_protocol_id_followed_by_correct(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test protocol validates protocol ID."""
    caplog.set_level("DEBUG", logger="tmodbus.transport.async_tcp")
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=0.02)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start send_and_receive in the background
    task = asyncio.create_task(protocol.send_and_receive(1, pdu))

    # Give it time to setup
    await asyncio.sleep(0.01)

    # MBAP: tid=1, pid=1 (invalid!), len=3, uid=1
    response_data = b"\x00\x01\x00\x01\x00\x03\x01\x03\x04\x00\x01\x00\x00\x00\x03\x01\x03\x04"
    protocol.data_received(response_data)
    # Should log "garbage bytes" at debug level
    await task

    assert any("garbage bytes" in record.message for record in caplog.records)


async def test_protocol_send_and_receive_invalid_unit_id() -> None:
    """Test protocol validates unit ID."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start send_and_receive in the background (unit_id=1)
    task = asyncio.create_task(protocol.send_and_receive(1, pdu))

    # Give it time to setup
    await asyncio.sleep(0.01)

    # MBAP: tid=1, pid=0, len=3, uid=2 (wrong unit!)
    response_data = b"\x00\x01\x00\x00\x00\x03\x02\x03\x04"
    protocol.data_received(response_data)

    with pytest.raises(InvalidResponseError, match="Unit ID mismatch"):
        await task


async def test_protocol_send_and_receive_success() -> None:
    """Test successful send and receive through protocol."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Start send_and_receive in the background
    task = asyncio.create_task(protocol.send_and_receive(1, pdu))

    # Give it time to setup
    await asyncio.sleep(0.01)

    # Simulate receiving a valid response
    # MBAP: tid=1, pid=0, len=3, uid=1 + PDU: 0x03 0x04
    response_data = b"\x00\x01\x00\x00\x00\x03\x01\x03\x04"
    protocol.data_received(response_data)

    result = await task
    assert result == ("decoded", b"\x03\x04")


async def test_on_connection_lost_callback() -> None:
    """Test _on_connection_lost sets transport and protocol to None."""
    t = AsyncTcpTransport("host", port=1234)
    t._transport = MagicMock()
    t._protocol = MagicMock()

    t._on_connection_lost(None)

    assert t._transport is None
    assert t._protocol is None


async def test_on_connection_lost_with_error() -> None:
    """Test _on_connection_lost logs error when provided."""
    t = AsyncTcpTransport("host", port=1234)
    t._transport = MagicMock()
    t._protocol = MagicMock()

    test_error = RuntimeError("test error")

    with patch("tmodbus.transport.async_tcp.logger") as log:
        t._on_connection_lost(test_error)
        log.error.assert_called()


async def test_close_closes_transport() -> None:
    """Test close actually closes the transport."""
    t = AsyncTcpTransport("host", port=1234)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    t._transport = mock_transport

    await t.close()

    mock_transport.close.assert_called_once()


async def test_protocol_data_received_partial_frame() -> None:
    """Test protocol handles partial frame data correctly."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    protocol.connection_made(mock_transport)

    # Create a pending request
    future: asyncio.Future[object] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = future  # type: ignore[assignment]

    # Send partial MBAP header first
    protocol.data_received(b"\x00\x01\x00\x00")

    # Should not be done yet
    assert not future.done()

    # Send rest of frame
    protocol.data_received(b"\x00\x03\x01\x03\x04")

    # Wait for processing
    await asyncio.sleep(0.01)

    assert future.done()


async def test_open_when_already_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that opening an already open transport returns early (lines 89-90)."""
    t = AsyncTcpTransport("host", port=1234)

    # Create real protocol and mock transport
    on_connection_lost_called = False

    def on_connection_lost(_exc: Exception | None) -> None:
        nonlocal on_connection_lost_called
        on_connection_lost_called = True

    mock_protocol = ModbusTcpProtocol(on_connection_lost=on_connection_lost, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    mock_protocol.connection_made(mock_transport)

    async def mock_create_connection(*_args: object, **_kwargs: object) -> tuple[object, object]:
        return mock_transport, mock_protocol

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_connection", mock_create_connection)

    # Open once
    await t.open()
    assert t.is_open()

    # Store the original protocol
    original_protocol = t._protocol

    # Try to open again - should return early with same protocol
    await t.open()
    assert t.is_open()
    assert t._protocol is original_protocol

    # Cleanup
    await t.close()


async def test_open_timeout_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that TimeoutError during open is handled (line 107)."""

    async def mock_create_connection(*_args: object, **_kwargs: object) -> tuple[None, None]:
        msg = "Connection timeout"
        raise TimeoutError(msg)

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_connection", mock_create_connection)

    t = AsyncTcpTransport("host", port=1234)
    # The TimeoutError should be passed on
    with pytest.raises(TimeoutError):
        await t.open()


async def test_close_with_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that exceptions during close are handled (lines 123-124)."""
    t = AsyncTcpTransport("host", port=1234)

    # Mock create_connection to open transport
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    mock_protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)

    async def mock_create_connection(*_args: object, **_kwargs: object) -> tuple[object, object]:
        return mock_transport, mock_protocol

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_connection", mock_create_connection)

    await t.open()

    # Mock transport.close() to raise exception
    mock_transport.close.side_effect = RuntimeError("Close failed")

    # Close should handle the exception gracefully
    await t.close()


async def test_protocol_transaction_id_mismatch() -> None:
    """Test that transaction ID mismatch raises InvalidResponseError (lines 265-269)."""
    # Test the protocol directly to cover lines 265-269
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    # Create a dummy PDU
    pdu = _DummyPDU()

    # Start a send_and_receive request with transaction ID 1
    task = asyncio.create_task(protocol.send_and_receive(unit_id=1, pdu=pdu))

    # Give it time to set up the pending request
    await asyncio.sleep(0.01)

    # Send a response with wrong transaction ID (2 instead of 1)
    # MBAP: trans_id=2, proto_id=0, length=3, unit_id=1, PDU=\x03\x04
    wrong_response = b"\x00\x02\x00\x00\x00\x03\x01\x03\x04"
    protocol.data_received(wrong_response)

    # Wait for processing
    await asyncio.sleep(0.01)

    # Now send correct response with transaction ID 1
    correct_response = b"\x00\x01\x00\x00\x00\x03\x01\x03\x04"
    protocol.data_received(correct_response)

    # The task should complete successfully with the correct response
    result = await task
    assert result == ("decoded", b"\x03\x04")


async def test_protocol_data_received_insufficient_buffer() -> None:
    """Test protocol with buffer less than 7 bytes (branch 301->295)."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    protocol.connection_made(mock_transport)

    # Send data less than 7 bytes (MBAP header size)
    protocol.data_received(b"\x00\x01\x00")

    # Should not process anything yet
    assert len(protocol._buffer) == 3
    assert len(protocol._pending_requests) == 0


async def test_protocol_data_received_incomplete_pdu() -> None:
    """Test protocol with complete MBAP header but incomplete PDU data (branch 292->286)."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    protocol.connection_made(mock_transport)

    # Create a pending request
    future: asyncio.Future[object] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = future  # type: ignore[assignment]

    # Send complete MBAP header that says we need 10 bytes of PDU data
    # MBAP: trans_id=1, proto_id=0, length=11 (10 bytes PDU + 1 byte unit_id), unit_id=1
    # But only send 7 bytes of MBAP header + 5 bytes of PDU (incomplete)
    incomplete_data = b"\x00\x01\x00\x00\x00\x0b\x01\x03\x04\x05\x06\x07"
    protocol.data_received(incomplete_data)

    # Should not be done yet - waiting for more data
    assert not future.done()
    # Buffer should still contain the incomplete frame
    assert len(protocol._buffer) == 12

    # Now send the rest of the PDU data
    remaining_data = b"\x08\x09\x0a\x0b\x0c"
    protocol.data_received(remaining_data)

    # Wait for processing
    await asyncio.sleep(0.01)

    # Now it should be complete
    assert future.done()


async def test_connection_lost_with_pending_requests() -> None:
    """Test that connection_lost sets exception on pending requests (lines 343-344)."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)

    # Create a mock that passes isinstance check for asyncio.WriteTransport
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    # Create a dummy PDU
    pdu = _DummyPDU()

    # Start a send_and_receive request - this creates a pending future
    task = asyncio.create_task(protocol.send_and_receive(unit_id=1, pdu=pdu))

    # Give it time to set up the pending request
    await asyncio.sleep(0.01)

    # Verify there's a pending request
    assert len(protocol._pending_requests) == 1

    # Now simulate connection lost
    test_exception = RuntimeError("Network error")
    protocol.connection_lost(test_exception)

    # The task should receive a ModbusConnectionError
    with pytest.raises(ModbusConnectionError, match="Connection lost before response was received"):
        await task

    # Pending requests should be cleared
    assert len(protocol._pending_requests) == 0


async def test_connection_lost_with_already_done_future() -> None:
    """Test that connection_lost skips already-done futures (branch 343->342)."""
    protocol = ModbusTcpProtocol(on_connection_lost=lambda _: None, timeout=10.0)

    # Create a mock that passes isinstance check for asyncio.WriteTransport
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    # Create a dummy PDU
    pdu = _DummyPDU()

    # Start a send_and_receive request - this creates a pending future
    task = asyncio.create_task(protocol.send_and_receive(unit_id=1, pdu=pdu))

    # Give it time to set up the pending request
    await asyncio.sleep(0.01)

    # Verify there's a pending request
    assert len(protocol._pending_requests) == 1
    transaction_id = next(iter(protocol._pending_requests.keys()))

    # Simulate receiving a response - this completes the future
    # MBAP: tid=transaction_id, pid=0, len=3, uid=1 + PDU: 0x03 0x04
    response_data = struct.pack(">HHHB", transaction_id, 0, 3, 1) + b"\x03\x04"
    protocol.data_received(response_data)

    # Wait for the task to complete successfully
    result = await task
    assert result == ("decoded", b"\x03\x04")

    # Now manually add the future back to pending_requests (as if it wasn't cleaned up)
    # This simulates the edge case where connection_lost is called with a done future
    future = asyncio.get_event_loop().create_future()
    future.set_result("already done")
    protocol._pending_requests[transaction_id] = future

    # Now call connection_lost - it should skip the already-done future
    protocol.connection_lost(None)

    # The future should still have its original result, not an exception
    assert future.result() == "already done"

    # Pending requests should be cleared
    assert len(protocol._pending_requests) == 0


async def test_transport_send_and_receive_delegates_to_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that AsyncTcpTransport.send_and_receive delegates to protocol (line 144)."""
    t = AsyncTcpTransport("host", port=1234)

    # Create mock protocol and transport
    mock_protocol = MagicMock(spec=ModbusTcpProtocol)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False

    # Mock the protocol's send_and_receive to return a known value
    expected_result = ("decoded", b"\x03\x04")
    mock_protocol.send_and_receive = AsyncMock(return_value=expected_result)

    async def mock_create_connection(*_args: object, **_kwargs: object) -> tuple[object, object]:
        return mock_transport, mock_protocol

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_connection", mock_create_connection)

    # Open the transport
    await t.open()
    assert t.is_open()

    # Create a dummy PDU
    pdu = _DummyPDU()

    # Call send_and_receive - this should delegate to the protocol
    result = await t.send_and_receive(unit_id=1, pdu=pdu)

    # Verify the result
    assert result == expected_result

    # Verify the protocol's send_and_receive was called with correct arguments
    mock_protocol.send_and_receive.assert_called_once_with(1, pdu)

    # Cleanup
    await t.close()
