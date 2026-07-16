"""Tests for tmodbus/transport/async_udp.py."""

import asyncio
import struct
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tmodbus.exceptions import (
    InvalidResponseError,
    ModbusConnectionError,
    ModbusResponseError,
    UnknownModbusResponseError,
)
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_udp import AsyncUdpTransport, ModbusUdpProtocol


class _DummyPDU(BaseClientPDU[tuple[str, bytes]]):
    function_code = 0x03

    def encode_request(self) -> bytes:
        return b"\x03\x04"

    def decode_response(self, data: bytes) -> tuple[str, bytes]:
        return ("decoded", data)


async def test_invalid_constructor_args() -> None:
    """Test that invalid constructor arguments raise ValueError."""
    with pytest.raises(ValueError, match=r"Port must be .*"):
        AsyncUdpTransport("host", port=0)
    with pytest.raises(ValueError, match=r"Timeout must .*"):
        AsyncUdpTransport("host", timeout=0)
    with pytest.raises(ValueError, match=r"Connect timeout must .*"):
        AsyncUdpTransport("host", connect_timeout=0)


async def test_open_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that connection errors during open are handled."""

    async def mock_create_datagram_endpoint(*_args: object, **_kwargs: object) -> tuple[None, None]:
        msg = "Connection failed"
        raise RuntimeError(msg)

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", mock_create_datagram_endpoint)

    t = AsyncUdpTransport("host", port=1234)
    with pytest.raises(ModbusConnectionError):
        await t.open()


async def test_open_respects_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """open() must give up after connect_timeout when the endpoint creation never completes."""

    async def never_connects(*_args: object, **_kwargs: object) -> tuple[None, None]:
        await asyncio.sleep(10)
        return None, None

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", never_connects)

    t = AsyncUdpTransport("host", port=1234, connect_timeout=0.05)
    with pytest.raises(TimeoutError):
        await t.open()
    assert not t.is_open()


async def test_is_open_false_when_not_connected() -> None:
    """Test is_open returns False when not connected."""
    t = AsyncUdpTransport("host", port=1234)
    assert not t.is_open()


async def test_send_and_receive_not_connected() -> None:
    """Test that sending when not connected raises ModbusConnectionError."""
    t = AsyncUdpTransport("host", port=1234)
    pdu = _DummyPDU()
    with pytest.raises(ModbusConnectionError):
        await t.send_and_receive(1, pdu)


async def test_close_already_closed() -> None:
    """Test that closing an already closed transport logs and returns early."""
    t = AsyncUdpTransport("host", port=1234)
    with patch("tmodbus.transport.async_udp.logger") as log:
        await t.close()
        log.debug.assert_called()


async def test_open_other_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that exceptions during open are logged and re-raised as ModbusConnectionError."""

    async def mock_create_datagram_endpoint(*_args: object, **_kwargs: object) -> tuple[None, None]:
        msg = "fail"
        raise RuntimeError(msg)

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", mock_create_datagram_endpoint)

    t = AsyncUdpTransport("host", port=1234)
    with patch("tmodbus.transport.async_udp.logger") as log:
        with pytest.raises(ModbusConnectionError):
            await t.open()
        log.exception.assert_called()


async def test_close_during_send_and_receive() -> None:
    """Test that a ModbusConnectionError is raised if the connection is closed during send_and_receive."""
    t = AsyncUdpTransport("host", port=1234)
    t._protocol = None
    with patch.object(t, "is_open", return_value=True):
        pdu = _DummyPDU()
        with pytest.raises(ModbusConnectionError):
            await t.send_and_receive(1, pdu)


async def test_is_open_with_transport() -> None:
    """Test is_open returns True when transport is connected."""
    t = AsyncUdpTransport("host", port=1234)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    t._transport = mock_transport

    assert t.is_open()


async def test_is_open_with_closing_transport() -> None:
    """Test is_open returns False when transport is closing."""
    t = AsyncUdpTransport("host", port=1234)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = True
    t._transport = mock_transport

    assert not t.is_open()


async def test_protocol_transaction_id_wraparound() -> None:
    """Test that Transaction ID wraps around after reaching 0xFFFF."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=10.0)

    protocol._next_transaction_id = 0xFFFF
    tid1 = protocol._get_next_transaction_id()
    tid2 = protocol._get_next_transaction_id()
    assert tid1 == 0xFFFF
    assert tid2 == 0


async def test_protocol_connection_made() -> None:
    """Test that connection_made is called correctly."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    protocol.connection_made(mock_transport)
    assert protocol.transport == mock_transport


async def test_protocol_connection_made_type_error() -> None:
    """Test that connection_made raises TypeError when transport is not a DatagramTransport."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)  # TCP transport
    with pytest.raises(TypeError, match="Expected a DatagramTransport"):
        protocol.connection_made(mock_transport)


async def test_protocol_send_and_receive_happy_path() -> None:
    """Test successful send_and_receive."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=1.0)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    # Simulate response arriving in the event loop
    async def simulate_recv() -> None:
        await asyncio.sleep(0.05)
        # response: tx_id=1, proto_id=0, length=4, unit_id=1, pdu=b"\x03\x99"
        resp_data = struct.pack(">HHHB", 1, 0, 3, 1) + b"\x03\x99"
        protocol.datagram_received(resp_data, None)

    task = asyncio.create_task(simulate_recv())
    res = await protocol.send_and_receive(unit_id=1, pdu=pdu)
    await task

    # Assert request sent correctly
    expected_request = struct.pack(">HHHB", 1, 0, 3, 1) + b"\x03\x04"
    mock_transport.sendto.assert_called_once_with(expected_request)
    assert res == ("decoded", b"\x03\x99")


async def test_protocol_send_and_receive_timeout() -> None:
    """Test timeout in send_and_receive."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    with pytest.raises(TimeoutError, match=r"Response timeout after .*"):
        await protocol.send_and_receive(unit_id=1, pdu=pdu)


async def test_protocol_datagram_received_invalid_length() -> None:
    """Test packet too short is discarded and logged as error."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    # Less than 7 bytes
    with (
        patch("tmodbus.transport.async_udp.logger") as mock_logger,
        patch("tmodbus.transport.async_udp.log_raw_traffic") as mock_log,
    ):
        protocol.datagram_received(b"\x00\x01\x00\x00\x00\x01", None)
        mock_logger.warning.assert_called_with("Received UDP packet too short: %d bytes", 6)
        mock_log.assert_called_once_with("recv", b"\x00\x01\x00\x00\x00\x01", is_error=True)


async def test_protocol_datagram_received_invalid_protocol_id() -> None:
    """Test invalid protocol ID is discarded and logged as error."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=10.0)

    data = struct.pack(">HHHB", 1, 1, 2, 1) + b"\x03"
    with (
        patch("tmodbus.transport.async_udp.logger") as mock_logger,
        patch("tmodbus.transport.async_udp.log_raw_traffic") as mock_log,
    ):
        protocol.datagram_received(data, None)
        mock_logger.warning.assert_called_with("Received UDP packet with invalid Protocol ID: %d", 1)
        mock_log.assert_called_once_with("recv", data, is_error=True)


async def test_protocol_datagram_received_length_mismatch() -> None:
    """Test length mismatch is discarded and logged as error."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    # length field = 5, but we send shorter PDU
    data = struct.pack(">HHHB", 1, 0, 5, 1) + b"\x03\x04"
    with (
        patch("tmodbus.transport.async_udp.logger") as mock_logger,
        patch("tmodbus.transport.async_udp.log_raw_traffic") as mock_log,
    ):
        protocol.datagram_received(data, None)
        mock_logger.warning.assert_called_with("Received UDP packet length mismatch: expected %d, got %d", 11, 9)
        mock_log.assert_called_once_with("recv", data, is_error=True)


async def test_protocol_datagram_received_unit_id_mismatch() -> None:
    """Test unit ID mismatch raises InvalidResponseError."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    async def simulate_recv() -> None:
        await asyncio.sleep(0.05)
        # response has unit_id = 2, expected 1
        resp_data = struct.pack(">HHHB", 1, 0, 3, 2) + b"\x03\x99"
        protocol.datagram_received(resp_data, None)

    task = asyncio.create_task(simulate_recv())
    with pytest.raises(InvalidResponseError, match="Unit ID mismatch"):
        await protocol.send_and_receive(unit_id=1, pdu=pdu)
    await task


async def test_protocol_datagram_received_exception_response() -> None:
    """Test that exception responses translate to exceptions."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    async def simulate_recv() -> None:
        await asyncio.sleep(0.05)
        # PDU has function code 0x03 | 0x80 = 0x83 (exception) and exception code 0x01
        resp_data = struct.pack(">HHHB", 1, 0, 3, 1) + b"\x83\x01"
        protocol.datagram_received(resp_data, None)

    task = asyncio.create_task(simulate_recv())
    # Exception code 0x01 is Illegal Function
    with pytest.raises(ModbusResponseError):
        await protocol.send_and_receive(unit_id=1, pdu=pdu)
    await task


async def test_protocol_error_received() -> None:
    """Test that error_received does not abort pending futures/requests."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=1.0)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    async def simulate_events() -> None:
        await asyncio.sleep(0.02)
        # 1. Trigger an asynchronous ICMP error
        protocol.error_received(ConnectionRefusedError("ICMP Port Unreachable"))
        await asyncio.sleep(0.02)
        # 2. Trigger the actual valid response to verify the future is still alive
        resp_data = struct.pack(">HHHB", 1, 0, 3, 1) + b"\x03\x99"
        protocol.datagram_received(resp_data, None)

    task = asyncio.create_task(simulate_events())
    res = await protocol.send_and_receive(unit_id=1, pdu=pdu)
    await task

    assert res == ("decoded", b"\x03\x99")


async def test_protocol_datagram_received_unexpected_ignored() -> None:
    """Test that an unexpected response is discarded and logged as ignored."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=10.0)
    # Valid datagram, but transaction ID 999 is unexpected/ignored
    data = struct.pack(">HHHB", 999, 0, 3, 1) + b"\x03\x04"
    with (
        patch("tmodbus.transport.async_udp.logger") as mock_logger,
        patch("tmodbus.transport.async_udp.log_raw_traffic") as mock_log,
    ):
        protocol.datagram_received(data, None)
        mock_logger.warning.assert_called_once()
        mock_log.assert_called_once_with("recv", data, is_ignored=True)


async def test_open_called_twice() -> None:
    """Test calling open() twice returns early."""
    t = AsyncUdpTransport("host", port=1234)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    t._transport = mock_transport
    t._protocol = MagicMock()
    with patch("tmodbus.transport.async_udp.logger") as log:
        await t.open()
        log.debug.assert_called_with("Async UDP connection already open: %s:%d", "host", 1234)


async def test_open_success_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful open() flow."""
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    mock_protocol = MagicMock(spec=ModbusUdpProtocol)

    async def mock_create_datagram_endpoint(*_args: object, **_kwargs: object) -> tuple[Any, Any]:
        return mock_transport, mock_protocol

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "create_datagram_endpoint", mock_create_datagram_endpoint)

    t = AsyncUdpTransport("host", port=1234)
    await t.open()
    assert t.is_open()


async def test_close_success() -> None:
    """Test successful close()."""
    t = AsyncUdpTransport("host", port=1234)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    t._transport = mock_transport

    await t.close()
    mock_transport.close.assert_called_once()


async def test_close_raises_exception() -> None:
    """Test that exceptions during close are swallowed."""
    t = AsyncUdpTransport("host", port=1234)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    mock_transport.close.side_effect = RuntimeError("close failed")
    t._transport = mock_transport

    with patch("tmodbus.transport.async_udp.logger") as log:
        await t.close()
        log.debug.assert_called()


async def test_on_connection_lost_with_exception() -> None:
    """Test on_connection_lost callback with exception and notify user callback."""
    cb = MagicMock()
    t = AsyncUdpTransport("host", port=1234, on_connection_lost=cb)
    exc = RuntimeError("lost")
    t._on_connection_lost(exc)
    cb.assert_called_once_with(exc)


async def test_on_connection_lost_clean() -> None:
    """Test on_connection_lost callback with clean exit."""
    cb = MagicMock()
    t = AsyncUdpTransport("host", port=1234, on_connection_lost=cb)
    t._on_connection_lost(None)
    cb.assert_called_once_with(None)


async def test_transport_send_and_receive_delegates() -> None:
    """Test AsyncUdpTransport.send_and_receive delegates to protocol."""
    t = AsyncUdpTransport("host", port=1234)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    t._transport = mock_transport

    mock_proto = AsyncMock()
    t._protocol = mock_proto

    pdu = _DummyPDU()
    await t.send_and_receive(1, pdu)
    mock_proto.send_and_receive.assert_called_once_with(1, pdu)


async def test_protocol_send_and_receive_not_connected() -> None:
    """Test ModbusUdpProtocol.send_and_receive raises when not connected."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=1.0)
    # no transport set
    pdu = _DummyPDU()
    with pytest.raises(ModbusConnectionError, match=r"Not connected\."):
        await protocol.send_and_receive(1, pdu)


async def test_protocol_send_and_receive_unknown_exception_code() -> None:
    """Test exception response with unknown exception code."""
    protocol = ModbusUdpProtocol(on_connection_lost=lambda _: None, timeout=1.0)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()

    async def simulate_recv() -> None:
        await asyncio.sleep(0.05)
        # response has exception code 0x09 (which is not in standard map)
        resp_data = struct.pack(">HHHB", 1, 0, 3, 1) + b"\x83\x09"
        protocol.datagram_received(resp_data, None)

    task = asyncio.create_task(simulate_recv())

    with pytest.raises(UnknownModbusResponseError):
        await protocol.send_and_receive(unit_id=1, pdu=pdu)
    await task


async def test_protocol_connection_lost_notifies_futures_and_callback() -> None:
    """Test that connection_lost cancels pending futures and calls user callback."""
    cb = MagicMock()
    protocol = ModbusUdpProtocol(on_connection_lost=cb, timeout=1.0)
    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    mock_transport.is_closing.return_value = False
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    task = asyncio.create_task(protocol.send_and_receive(1, pdu))

    # Add a done future to cover the branch where not future.done() is False
    done_future = asyncio.get_event_loop().create_future()
    done_future.set_result(None)
    protocol._pending_requests[999] = done_future

    await asyncio.sleep(0.01)
    exc = ConnectionResetError("lost connection")
    protocol.connection_lost(exc)

    with pytest.raises(ModbusConnectionError, match=r"Connection lost before response was received\."):
        await task

    cb.assert_called_once_with(exc)
