"""Tests for tmodbus/transport/async_rtu.py with Protocol-based architecture."""

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import serial_asyncio_fast
from tmodbus.exceptions import (
    CRCError,
    IllegalFunctionError,
    InvalidResponseError,
    ModbusConnectionError,
    RTUFrameError,
)
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_rtu import (
    MAX_RTU_FRAME_SIZE,
    AsyncRtuTransport,
    ModbusRtuProtocol,
    _ModbusRtuMessage,
    compute_interframe_delay,
    compute_max_continuous_transmission_delay,
)
from tmodbus.utils.crc import calculate_crc16


def test_compute_delays() -> None:
    """Test computation of interframe and max continuous transmission delays."""
    # baudrate >= 19200 uses at least 1.75ms
    d = compute_interframe_delay(11 / 19200)
    assert d >= 0.00175
    # lower baudrate increases delay
    one_char = 11 / 9600
    assert compute_interframe_delay(one_char) >= 3.5 * one_char
    assert compute_max_continuous_transmission_delay(one_char) == pytest.approx(1.5 * one_char)


class _DummyPDU(BaseClientPDU[tuple[str, bytes]]):
    function_code = 0x03

    def encode_request(self) -> bytes:
        return b"\x03\x00"

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
) -> tuple[MagicMock, Callable[[], ModbusRtuProtocol | None]]:
    """Fixture to mock serial_asyncio_fast.create_serial_connection."""
    created_protocol: ModbusRtuProtocol | None = None

    async def fake_create_serial_connection(
        _loop: Any, protocol_factory: Callable[[], ModbusRtuProtocol], **_kwargs: Any
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

    # Return transport and a callable to get the protocol
    return mock_transport, lambda: created_protocol


async def test_open_already_open() -> None:
    """Test that open early-returns if already open and logs debug."""
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)

    # Mock create_serial_connection to setup transport/protocol
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

        # Second open should early-return and log debug
        with patch("tmodbus.transport.async_rtu.logger") as log:
            await t.open()
            log.debug.assert_called()


async def test_open_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that open raises TimeoutError when create_serial_connection times out."""
    monkeypatch.setattr(
        "serial_asyncio_fast.create_serial_connection",
        AsyncMock(side_effect=asyncio.TimeoutError),
    )
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    with pytest.raises(TimeoutError):
        await t.open()


@pytest.mark.usefixtures("mock_serial_connection")
async def test_open_close_is_open() -> None:
    """Test open, close, and is_open functionality."""
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()
    assert t.is_open()

    # When we close, the transport should call connection_lost callback
    # Simulate that by calling it after close
    if t._protocol:
        t._protocol.connection_lost(None)

    assert not t.is_open()


async def test_send_and_receive_success(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test successful send_and_receive with a valid response."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    # Prepare response data
    pdu = _DummyPDU()
    unit_id = 1
    response_data = b"\x05"
    payload = bytes([unit_id, pdu.function_code]) + response_data
    crc = calculate_crc16(payload)
    response_adu = payload + crc

    # Mock get_pdu_class to return a dummy class with expected length 1
    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)

    # Set last frame time to avoid inter-frame delay
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Send request in background and simulate receiving response
    async def simulate_response() -> None:
        await asyncio.sleep(0.01)  # Small delay to let send_and_receive start
        protocol.data_received(response_adu)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    result = await result_task
    await response_task

    assert result[0] == "decoded"


async def test_send_and_receive_not_connected() -> None:
    """Test that send_and_receive raises ModbusConnectionError when not connected."""
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    # Don't open the connection
    with pytest.raises(ModbusConnectionError, match=r"not connected"):
        await t.send_and_receive(1, _DummyPDU())


async def test_protocol_send_and_receive_not_connected() -> None:
    """Test that send_and_receive raises ModbusConnectionError when not connected."""
    p = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    # Don't open the connection
    with pytest.raises(ModbusConnectionError, match=r"Not connected"):
        await p.send_and_receive(1, _DummyPDU())


async def test_send_and_receive_crc_error(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that send_and_receive raises CRCError on invalid CRC."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    response_data = b"\x05"
    payload = bytes([unit_id, pdu.function_code]) + response_data
    # Use wrong CRC
    response_adu = payload + b"\x00\x00"

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    with pytest.raises(CRCError):
        await result_task
    await response_task


async def test_send_and_receive_address_mismatch(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that send_and_receive validates the unit_id in the response."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    wrong_unit_id = 2  # Response has wrong unit_id
    response_data = b"\x05"
    # Build response with wrong unit_id but correct function code
    payload = bytes([wrong_unit_id, pdu.function_code]) + response_data
    crc = calculate_crc16(payload)
    wrong_response = payload + crc

    # Build correct response
    correct_payload = bytes([unit_id, pdu.function_code]) + response_data
    correct_crc = calculate_crc16(correct_payload)
    correct_response = correct_payload + correct_crc

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        # First send wrong response (will be discarded as garbage)
        protocol.data_received(wrong_response)
        await asyncio.sleep(0.01)
        # Then send correct response
        protocol.data_received(correct_response)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    # Should succeed with correct response after discarding wrong one
    result = await result_task
    await response_task

    assert result[0] == "decoded"


async def test_send_and_receive_exception_response(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that send_and_receive raises appropriate exception for exception response."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    # Exception response: function code | 0x80, exception code 0x01 (illegal function)
    payload = bytes([unit_id, pdu.function_code | 0x80, 0x01])
    crc = calculate_crc16(payload)
    response_adu = payload + crc

    # Create a dummy PDU class for exception responses
    class DummyExceptionPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 0

    monkeypatch.setattr(
        "tmodbus.transport.async_rtu.get_pdu_class",
        lambda _: DummyExceptionPduClass(),
    )
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    with pytest.raises(IllegalFunctionError):
        await result_task
    await response_task


async def test_send_and_receive_timeout(
    mock_transport: MagicMock,
) -> None:
    """Test that send_and_receive raises TimeoutError when no response is received."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.2)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu = _DummyPDU()
    unit_id = 1

    with pytest.raises(TimeoutError, match="timeout"):
        await protocol.send_and_receive(unit_id, pdu)


async def test_protocol_garbage_data_handling(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that protocol handles garbage data by searching for expected unit_id."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    response_data = b"\x05"
    payload = bytes([unit_id, pdu.function_code]) + response_data
    crc = calculate_crc16(payload)
    response_adu = payload + crc

    # Prepend garbage data
    garbage = b"\xff\xfe\xfd"
    data_with_garbage = garbage + response_adu

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        # Send garbage followed by valid response
        protocol.data_received(data_with_garbage)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    result = await result_task
    await response_task

    assert result[0] == "decoded"


async def test_protocol_per_unit_request_tracking(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that protocol tracks pending requests per unit_id."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu1 = _DummyPDU()
    pdu2 = _DummyPDU()
    unit_id_1 = 1
    unit_id_2 = 2

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Start two requests for different units simultaneously
    async def send_and_respond(unit_id: int, pdu: BaseClientPDU) -> Any:  # type: ignore[type-arg]
        response_data = b"\x05"
        payload = bytes([unit_id, pdu.function_code]) + response_data
        crc = calculate_crc16(payload)
        response_adu = payload + crc

        async def simulate_response() -> None:
            await asyncio.sleep(0.02)
            protocol.data_received(response_adu)

        result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
        response_task = asyncio.create_task(simulate_response())

        result = await result_task
        await response_task
        return result

    # Send requests to two different units - should work concurrently
    result1, result2 = await asyncio.gather(
        send_and_respond(unit_id_1, pdu1),
        send_and_respond(unit_id_2, pdu2),
    )

    assert result1[0] == "decoded"
    assert result2[0] == "decoded"


async def test_protocol_waits_for_previous_request_same_unit(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that protocol waits for previous request to same unit to complete."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu1 = _DummyPDU()
    pdu2 = _DummyPDU()
    unit_id = 1

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    request1_started = False
    request2_started = False

    async def send_request_1() -> Any:
        nonlocal request1_started
        request1_started = True

        response_data = b"\x05"
        payload = bytes([unit_id, pdu1.function_code]) + response_data
        crc = calculate_crc16(payload)
        response_adu = payload + crc

        async def simulate_response() -> None:
            await asyncio.sleep(0.05)
            protocol.data_received(response_adu)

        result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu1))
        response_task = asyncio.create_task(simulate_response())

        result = await result_task
        await response_task
        return result

    async def send_request_2() -> Any:
        # Wait a bit to ensure request1 starts first
        await asyncio.sleep(0.01)
        nonlocal request2_started
        request2_started = True

        response_data = b"\x06"
        payload = bytes([unit_id, pdu2.function_code]) + response_data
        crc = calculate_crc16(payload)
        response_adu = payload + crc

        async def simulate_response() -> None:
            await asyncio.sleep(0.01)
            protocol.data_received(response_adu)

        result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
        response_task = asyncio.create_task(simulate_response())

        result = await result_task
        await response_task
        return result

    # Both requests should complete, but request2 waits for request1
    result1, result2 = await asyncio.gather(
        send_request_1(),
        send_request_2(),
    )

    assert request1_started
    assert request2_started
    assert result1[0] == "decoded"
    assert result2[0] == "decoded"


async def test_connection_lost_sets_exception_on_pending_requests(
    mock_transport: MagicMock,
) -> None:
    """Test that connection_lost sets exception on all pending requests."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
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


async def test_open_raises_modbus_connection_error_on_generic_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that open raises ModbusConnectionError when create_serial_connection fails."""
    monkeypatch.setattr(
        "serial_asyncio_fast.create_serial_connection",
        AsyncMock(side_effect=RuntimeError("Serial error")),
    )
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    with pytest.raises(ModbusConnectionError):
        await t.open()


async def test_close_when_already_closed(caplog: pytest.LogCaptureFixture) -> None:
    """Test that close logs debug when connection is already closed."""
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)

    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_rtu"):
        await t.close()
        assert any("already closed" in record.message.lower() for record in caplog.records)


@pytest.mark.usefixtures("mock_serial_connection")
async def test_close(caplog: pytest.LogCaptureFixture) -> None:
    """Test that close handles exceptions during close."""
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()

    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_rtu"):
        await t.close()
        assert len(caplog.records) > 0


async def test_close_with_exception(
    mock_serial_connection: tuple[MagicMock, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that close handles exceptions during close."""
    mock_transport, _get_protocol = mock_serial_connection

    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()

    # Make transport.close() raise an exception
    mock_transport.close.side_effect = RuntimeError("Close failed")

    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_rtu"):
        await t.close()
        assert len(caplog.records) > 0


async def test_on_connection_lost_with_exception(caplog: pytest.LogCaptureFixture) -> None:
    """Test that _on_connection_lost logs error when exc is not None."""
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)

    with caplog.at_level(logging.ERROR, logger="tmodbus.transport.async_rtu"):
        t._on_connection_lost(RuntimeError("Connection error"))
        assert any(record.levelname == "ERROR" for record in caplog.records)


async def test_on_connection_lost_without_exception(caplog: pytest.LogCaptureFixture) -> None:
    """Test that _on_connection_lost logs info when exc is None."""
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)

    with caplog.at_level(logging.INFO, logger="tmodbus.transport.async_rtu"):
        t._on_connection_lost(None)
        assert any(record.levelname == "INFO" for record in caplog.records)


async def test_transport_send_and_receive() -> None:
    """Test that send_and_receive calls protocol's send_and_receive."""
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600, timeout=0.1)
    t._protocol = MagicMock(spec=ModbusRtuProtocol)

    t._transport = MagicMock(spec=asyncio.WriteTransport)
    t._transport.is_closing.return_value = False

    await t.send_and_receive(1, _DummyPDU())
    assert t._protocol.send_and_receive.called


async def test_on_connection_lost_pending_futures(mock_serial_connection: tuple[MagicMock, Any]) -> None:
    """Test that _on_connection_lost sets exception on pending futures."""
    mock_transport, _get_protocol = mock_serial_connection
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    protocol = ModbusRtuProtocol(on_connection_lost=t._on_connection_lost)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1

    # add a future that is already done to _pending_requests to test that it is skipped
    done_future = asyncio.get_event_loop().create_future()
    done_future.set_result(None)
    protocol._pending_requests[2] = done_future

    # Start a send_and_receive to create a pending future
    send_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    await asyncio.sleep(0.01)  # Ensure the send_and_receive has started
    assert protocol._pending_requests[unit_id]
    # Now simulate connection lost
    protocol.connection_lost(None)

    with pytest.raises(ModbusConnectionError, match=r"Connection lost before response was received\."):
        await send_task


async def test_connection_made_with_wrong_transport_type() -> None:
    """Test that connection_made raises TypeError for non-WriteTransport."""
    protocol = ModbusRtuProtocol(
        on_connection_lost=lambda _: None,
        timeout=10.0,
        interframe_delay=0.00175,
    )

    # Create a transport that's not a WriteTransport
    mock_transport = MagicMock(spec=asyncio.BaseTransport)

    with pytest.raises(TypeError, match="Expected a WriteTransport"):
        protocol.connection_made(mock_transport)


async def test_send_and_receive_function_code_mismatch(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that send_and_receive raises InvalidResponseError on function code mismatch."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    wrong_function_code = 0x04  # Different from pdu.function_code (0x03)
    response_data = b"\x05"
    payload = bytes([unit_id, wrong_function_code]) + response_data
    crc = calculate_crc16(payload)
    response_adu = payload + crc

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    with pytest.raises(InvalidResponseError, match="Function code mismatch"):
        await result_task
    await response_task


async def test_garbage_data_no_pending_requests(
    mock_transport: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test garbage handling when there are no pending requests."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    # Send garbage data when no requests are pending
    garbage = b"\xff\xfe\xfd\xfc"

    with caplog.at_level(logging.WARNING, logger="tmodbus.transport.async_rtu"):
        protocol.data_received(garbage)

        # Should log warning about discarding data with no pending requests
        assert any("no pending requests" in record.message for record in caplog.records)
        # Buffer should be cleared
        assert len(protocol._buffer) == 0


async def test_garbage_data_unexpected_state(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test garbage handling in unexpected state (should not normally happen)."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Start a request to create a pending request for unit_id 1
    response_data = b"\x05"
    payload = bytes([unit_id, pdu.function_code]) + response_data
    crc = calculate_crc16(payload)
    response_adu = payload + crc

    async def send_request_and_trigger_unexpected_state() -> tuple[str, bytes]:
        async def simulate_response() -> None:
            await asyncio.sleep(0.01)
            # Add a byte for a different unit (2) that has no pending request
            # This should trigger the garbage handling
            garbage_byte = bytes([2])  # Unit ID 2 with no pending request
            protocol.data_received(garbage_byte)
            await asyncio.sleep(0.01)
            # Now send the real response
            protocol.data_received(response_adu)

        result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
        response_task = asyncio.create_task(simulate_response())

        result = await result_task
        await response_task
        return result

    with caplog.at_level(logging.WARNING, logger="tmodbus.transport.async_rtu"):
        result = await send_request_and_trigger_unexpected_state()
        assert result[0] == "decoded"

        # Should have logged about discarding bytes
        assert any("Discarding" in record.message for record in caplog.records)


async def test_exception_response_empty_pdu(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test exception response with empty pdu_bytes."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.02)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    # Exception response with only function code, no exception code
    payload = bytes([unit_id, pdu.function_code | 0x80])
    crc = calculate_crc16(payload)
    response_adu = payload + crc

    class DummyExceptionPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 0

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyExceptionPduClass())

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    with pytest.raises(TimeoutError):
        await result_task
    await response_task


async def test_frame_exceeds_max_size(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that frame size exceeding max raises RTUFrameError."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.02)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1

    # Mock get_pdu_class to return a huge expected length
    class OversizedPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return MAX_RTU_FRAME_SIZE + 100  # Exceeds max

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: OversizedPduClass())
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        # Send enough data to trigger the check
        payload = bytes([unit_id, pdu.function_code]) + b"\x00" * (MAX_RTU_FRAME_SIZE + 1000)
        crc = calculate_crc16(payload)
        protocol.data_received(payload + crc)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    with pytest.raises(RTUFrameError, match="Expected frame length"):
        await result_task
    await response_task


async def test_pending_future_already_done(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that we don't set result on already-done future."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    response_data = b"\x05"
    payload = bytes([unit_id, pdu.function_code]) + response_data
    crc = calculate_crc16(payload)
    response_adu = payload + crc

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.05)
        # By this time, the request should be cancelled
        # Try to send response anyway
        protocol.data_received(response_adu)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    # Cancel the request task immediately
    await asyncio.sleep(0.01)
    result_task.cancel()

    with contextlib.suppress(asyncio.CancelledError):
        await result_task

    await response_task

    # If we get here without exceptions, the test passes


async def test_timeout_not_none_in_pyserial_options() -> None:
    """Test that explicit timeout in pyserial_options is used (line 153)."""
    # This tests the branch where timeout is NOT None
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600, timeout=5.0)
    assert t.timeout == 5.0


async def test_send_and_receive_previous_request_timeout(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test waiting for previous request that times out (lines 329-330)."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.1)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Directly test the code path by mocking a pending future that will timeout
    mock_future: asyncio.Future[Any] = asyncio.Future()
    protocol._pending_requests[unit_id] = mock_future

    # Now when we call send_and_receive, it should wait for the mock_future
    # which will timeout
    response_data = b"\x05"
    payload = bytes([unit_id, pdu.function_code]) + response_data
    crc = calculate_crc16(payload)
    response_adu = payload + crc

    async def send_after_delay() -> None:
        await asyncio.sleep(0.15)  # After the timeout
        protocol.data_received(response_adu)

    with patch("tmodbus.transport.async_rtu.logger") as log:
        send_task = asyncio.create_task(send_after_delay())

        # This should log about timeout while waiting for the mock_future
        result = await protocol.send_and_receive(unit_id, pdu)
        await send_task

        # Should have logged about timeout
        assert any("timed out" in str(call) for call in log.debug.call_args_list)
        assert result[0] == "decoded"


async def test_send_and_receive_previous_request_failed(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test waiting for previous request that has failed."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.1)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Directly test the code path by mocking a pending future that has failed
    mock_future: asyncio.Future[Any] = asyncio.Future()
    protocol._pending_requests[unit_id] = mock_future

    # Now when we call send_and_receive, it should wait for the mock_future
    # which will timeout
    response_data = b"\x05"
    payload = bytes([unit_id, pdu.function_code]) + response_data
    crc = calculate_crc16(payload)
    response_adu = payload + crc

    async def error_after_delay() -> None:
        await asyncio.sleep(0.01)
        mock_future.set_exception(RuntimeError("Previous request failed"))
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu)

    with patch("tmodbus.transport.async_rtu.logger") as log:
        error_task = asyncio.create_task(error_after_delay())

        # This should log about timeout while waiting for the mock_future
        result = await protocol.send_and_receive(unit_id, pdu)
        await error_task

        # Should have logged about failed request
        assert any("failed" in str(call) for call in log.debug.call_args_list)
        assert result[0] == "decoded"


async def test_data_received_cannot_determine_length(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test data_received when PDU class raises error determining length (lines 462-464)."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1

    # Mock get_pdu_class to raise ValueError when determining length
    class BadPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            msg = "Cannot determine length"
            raise ValueError(msg)

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: BadPduClass())
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Start a request
    async def send_request_and_receive_partial() -> None:
        result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))

        # Send partial data that will trigger the ValueError
        await asyncio.sleep(0.01)
        partial_data = bytes([unit_id, pdu.function_code, 0x01])  # Incomplete
        protocol.data_received(partial_data)

        # Buffer should still contain the partial data (waiting for more)
        assert len(protocol._buffer) == 3

        # Cancel the request
        result_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await result_task

    await send_request_and_receive_partial()


async def test_determine_expected_frame_length__too_short(
    mock_transport: MagicMock,
) -> None:
    """Test data_received when PDU class raises error determining length (lines 462-464)."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    protocol._buffer.extend(b"\01")
    assert protocol._determine_expected_frame_length() is None


async def test_determine_expected_frame_length__too_short_subfunction_pdu(
    mock_transport: MagicMock,
) -> None:
    """Test data_received when PDU class raises error determining length (lines 462-464)."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    protocol._buffer.extend(bytes.fromhex("01 2B 0E"))
    assert protocol._determine_expected_frame_length() is None


async def test_determine_expected_frame_length__subfunction_pdu(
    mock_transport: MagicMock,
) -> None:
    """Test data_received when PDU class raises error determining length (lines 462-464)."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    protocol._buffer.extend(bytes.fromhex("01 2B 0E 01 01 00 "))
    assert protocol._determine_expected_frame_length() is None


async def test_data_received_insufficient_data(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test data_received returns early when insufficient data (line 468-469)."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 10  # Expecting 10 bytes of data

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Start a request
    async def send_request_and_receive_partial() -> None:
        result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))

        # Send partial data (less than expected)
        await asyncio.sleep(0.01)
        partial_data = bytes([unit_id, pdu.function_code, 0x01, 0x02])  # Only 2 bytes, need 10
        protocol.data_received(partial_data)

        # Buffer should still contain the partial data (waiting for more)
        assert len(protocol._buffer) == 4

        # Cancel the request
        result_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await result_task

    await send_request_and_receive_partial()


async def test_wait_on_pending_request_no_pending() -> None:
    """Test _wait_on_pending_request when there's no pending request for the unit_id."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)

    # Should return immediately when there's no pending request
    await protocol._wait_on_pending_request(1)
    # If we get here without blocking, the test passes


async def test_wait_on_pending_request_already_done() -> None:
    """Test _wait_on_pending_request when pending request is already done."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)

    # Create a future that's already done
    done_future: asyncio.Future[_ModbusRtuMessage] = asyncio.get_event_loop().create_future()
    done_future.set_result(_ModbusRtuMessage(unit_id=1, pdu_bytes=b"\x03\x00", crc=b"\x00\x00"))
    protocol._pending_requests[1] = done_future

    # Should return immediately when future is already done
    await protocol._wait_on_pending_request(1)
    # If we get here without blocking, the test passes


async def test_wait_on_pending_request_waits_for_completion(caplog: pytest.LogCaptureFixture) -> None:
    """Test _wait_on_pending_request waits for pending request to complete successfully."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=1.0)

    # Create a pending future
    pending_future: asyncio.Future[_ModbusRtuMessage] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = pending_future

    # Set up a task to complete the future after a delay
    async def complete_future() -> None:
        await asyncio.sleep(0.05)
        pending_future.set_result(_ModbusRtuMessage(unit_id=1, pdu_bytes=b"\x03\x00", crc=b"\x00\x00"))

    complete_task = asyncio.create_task(complete_future())

    # Should wait for the future to complete
    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_rtu"):
        await protocol._wait_on_pending_request(1)

        # Should have logged success
        assert any("succeeded" in record.message for record in caplog.records)

    await complete_task


async def test_wait_on_pending_request_cancelled(caplog: pytest.LogCaptureFixture) -> None:
    """Test _wait_on_pending_request when pending request is cancelled."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=1.0)

    # Create a pending future
    pending_future: asyncio.Future[_ModbusRtuMessage] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = pending_future

    # Set up a task to cancel the future after a delay
    async def cancel_future() -> None:
        await asyncio.sleep(0.05)
        pending_future.cancel()

    cancel_task = asyncio.create_task(cancel_future())

    # Should wait for the future and handle cancellation
    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_rtu"):
        await protocol._wait_on_pending_request(1)

        # Should have logged cancellation
        assert any("cancelled" in record.message for record in caplog.records)

    await cancel_task


async def test_wait_on_pending_request_generic_exception(caplog: pytest.LogCaptureFixture) -> None:
    """Test _wait_on_pending_request when pending request raises a generic exception."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=1.0)

    # Create a pending future
    pending_future: asyncio.Future[_ModbusRtuMessage] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = pending_future

    # Set up a task to fail the future after a delay
    async def fail_future() -> None:
        await asyncio.sleep(0.05)
        pending_future.set_exception(RuntimeError("Previous request error"))

    fail_task = asyncio.create_task(fail_future())

    # Should wait for the future and handle the exception
    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_rtu"):
        await protocol._wait_on_pending_request(1)

        # Should have logged the failure
        assert any("failed" in record.message for record in caplog.records)

    await fail_task


async def test_wait_on_pending_request_timeout_waiting(caplog: pytest.LogCaptureFixture) -> None:
    """Test _wait_on_pending_request when waiting times out."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.1)

    # Create a pending future that never completes
    pending_future: asyncio.Future[_ModbusRtuMessage] = asyncio.get_event_loop().create_future()
    protocol._pending_requests[1] = pending_future

    # Should timeout and log it
    with caplog.at_level(logging.DEBUG, logger="tmodbus.transport.async_rtu"):
        await protocol._wait_on_pending_request(1)

        # Should have logged timeout
        assert any("timed out" in record.message for record in caplog.records)
