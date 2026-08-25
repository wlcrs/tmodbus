"""Tests for tmodbus/transport/async_rtu.py with Protocol-based architecture."""

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import serialx
from tmodbus.exceptions import (
    CRCError,
    FunctionCodeError,
    IllegalFunctionError,
    InvalidRequestError,
    InvalidResponseError,
    ModbusConnectionError,
    RTUFrameError,
)
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.pdu.serial_line import DiagnosticsQueryDataPDU
from tmodbus.transport.async_rtu import (
    MAX_RTU_BUFFER_SIZE,
    MAX_RTU_FRAME_SIZE,
    AsyncRtuTransport,
    ModbusRtuProtocol,
    _ModbusRtuMessage,
    _PendingRequest,
    _validate_rtu_request_length,
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
    """Fixture to mock serialx.create_serial_connection."""
    created_protocol: ModbusRtuProtocol | None = None

    async def fake_create_serial_connection(
        _loop: Any, protocol_factory: Callable[[], ModbusRtuProtocol], **_kwargs: Any
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

    with patch.object(serialx, "create_serial_connection", fake_create_serial_connection):
        await t.open()
        assert t.is_open()

        # Second open should early-return and log debug
        with patch("tmodbus.transport.async_rtu.logger") as log:
            await t.open()
            log.debug.assert_called()


async def test_open_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that open raises TimeoutError when create_serial_connection times out."""
    monkeypatch.setattr(
        "serialx.create_serial_connection",
        AsyncMock(side_effect=asyncio.TimeoutError),
    )
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    with pytest.raises(TimeoutError):
        await t.open()


async def test_open_timeout_waiting_for_connection_made(monkeypatch: pytest.MonkeyPatch) -> None:
    """If connection_made never fires, open() times out and leaves no half-open transport."""
    mock_transport = MagicMock(spec=asyncio.WriteTransport)
    mock_transport.is_closing.return_value = False

    async def fake_create_serial_connection(
        _loop: Any, protocol_factory: Callable[[], ModbusRtuProtocol], **_kwargs: Any
    ) -> tuple[asyncio.Transport, asyncio.Protocol]:
        # Return a transport/protocol but never call connection_made.
        return mock_transport, protocol_factory()

    monkeypatch.setattr(serialx, "create_serial_connection", fake_create_serial_connection)

    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600, timeout=0.05)
    with pytest.raises(TimeoutError):
        await t.open()

    assert not t.is_open()
    mock_transport.close.assert_called_once()


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


async def test_send_and_receive_fifo_queue_framing(
    mock_transport: MagicMock,
) -> None:
    """Regression: FIFO responses use a two-byte byte count for RTU framing.

    The FIFO response (function code 0x18) does not carry its length in a single
    byte, so the transport must use the PDU's own length logic. With the wrong
    length the frame would be cut short and fail its CRC check.
    """
    from tmodbus.pdu import ReadFifoQueuePDU  # noqa: PLC0415

    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = ReadFifoQueuePDU(address=0x04DE)
    unit_id = 1
    # Spec V1.1b3 example response: byte count 0x0006, FIFO count 0x0002, values 0x01B8, 0x1234.
    response_pdu = bytes.fromhex("1800060002 01B8 1234".replace(" ", ""))
    payload = bytes([unit_id]) + response_pdu
    response_adu = payload + calculate_crc16(payload)

    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    result = await result_task
    await response_task

    assert result == [0x01B8, 0x1234]


async def test_send_and_receive_chunk_ends_after_function_code(
    mock_transport: MagicMock,
) -> None:
    """Regression: a chunk ending right after the function code must not crash framing.

    With only unit id + function code buffered there is no length byte yet, so the
    default length logic must report None (wait for more data) instead of raising
    IndexError inside data_received.
    """
    from tmodbus.pdu import ReadHoldingRegistersPDU  # noqa: PLC0415

    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = ReadHoldingRegistersPDU(start_address=0, quantity=2)
    unit_id = 1
    # Response: byte count 0x04, register values 0x0102, 0x0304.
    response_pdu = bytes.fromhex("03 04 0102 0304".replace(" ", ""))
    payload = bytes([unit_id]) + response_pdu
    response_adu = payload + calculate_crc16(payload)

    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu[:2])  # exactly unit id + function code
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu[2:])

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    result = await result_task
    await response_task

    assert result == [0x0102, 0x0304]


async def test_send_and_receive_exception_status_framing(
    mock_transport: MagicMock,
) -> None:
    """Regression: Read Exception Status frames as one status byte over RTU.

    The status byte is not a byte count, so a nonzero status (0xFF) must not be
    read as a length, which would otherwise frame the response far too long.
    """
    from tmodbus.pdu import ReadExceptionStatusPDU  # noqa: PLC0415

    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = ReadExceptionStatusPDU()
    unit_id = 1
    # Response PDU: function code 0x07 followed by status 0xFF (the value that
    # previously made framing wait for 256 extra bytes).
    response_pdu = bytes([0x07, 0xFF])
    payload = bytes([unit_id]) + response_pdu
    response_adu = payload + calculate_crc16(payload)

    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    result = await result_task
    await response_task

    assert result == 0xFF


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


async def test_send_and_receive_unsupported_function_code(
    mock_transport: MagicMock,
) -> None:
    """An unknown function code in a response must not crash the parser.

    A bit flip on the line can turn the function code into one this library does
    not know. The frame length cannot be determined, so the request should fail
    with an RTUFrameError instead of letting a ValueError escape data_received.
    """
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # function code 0x03
    unit_id = 1
    # Response carries an unsupported function code (0x65) for the pending unit.
    payload = bytes([unit_id, 0x65, 0x00, 0x00])
    response_adu = payload + calculate_crc16(payload)

    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        # This must not raise out of data_received.
        protocol.data_received(response_adu)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_response())

    with pytest.raises(FunctionCodeError):
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
    """Test that protocol tracks timed-out requests per unit_id across serialized transactions."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.05)
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

    # Request 1 times out -> stored in _timed_out_requests[unit_id_1]
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id_1, pdu1)

    assert protocol._timed_out_requests[unit_id_1] is pdu1

    # Request 2 succeeds -> stored in _timed_out_requests[unit_id_2] (if timed out), but unit 1 is kept
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    resp2_payload = bytes([unit_id_2, pdu2.function_code, 0x05])
    resp2_frame = resp2_payload + calculate_crc16(resp2_payload)

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id_2, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    protocol.data_received(resp2_frame)

    res2 = await req2_task

    assert res2[0] == "decoded"
    # Unit 1 timed-out request is still tracked safely!
    assert protocol._timed_out_requests[unit_id_1] is pdu1
    assert unit_id_2 not in protocol._timed_out_requests


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

    resp1 = bytes([unit_id, pdu1.function_code, 0x05])
    resp1_frame = resp1 + calculate_crc16(resp1)

    resp2 = bytes([unit_id, pdu2.function_code, 0x06])
    resp2_frame = resp2 + calculate_crc16(resp2)

    async def deliver_responses() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(resp1_frame)
        await asyncio.sleep(0.01)
        protocol.data_received(resp2_frame)

    task1 = asyncio.create_task(protocol.send_and_receive(unit_id, pdu1))
    task2 = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    deliv_task = asyncio.create_task(deliver_responses())

    result1, result2 = await asyncio.gather(task1, task2)
    await deliv_task

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
        "serialx.create_serial_connection",
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

    # Start a send_and_receive to create a pending future
    send_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    await asyncio.sleep(0.01)  # Ensure the send_and_receive has started
    assert protocol._pending_request is not None
    protocol._timed_out_requests[3] = pdu
    # Now simulate connection lost
    protocol.connection_lost(None)
    assert len(protocol._timed_out_requests) == 0
    assert protocol._pending_request is None

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
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=10.0)
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


async def test_send_and_receive_serialized_by_bus_lock(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that concurrent send_and_receive calls are serialized by the bus lock."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=1.0)
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

    resp1 = bytes([unit_id_1, pdu1.function_code, 0x05])
    resp1_frame = resp1 + calculate_crc16(resp1)

    resp2 = bytes([unit_id_2, pdu2.function_code, 0x06])
    resp2_frame = resp2 + calculate_crc16(resp2)

    async def deliver_responses() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(resp1_frame)
        await asyncio.sleep(0.01)
        protocol.data_received(resp2_frame)

    task1 = asyncio.create_task(protocol.send_and_receive(unit_id_1, pdu1))
    task2 = asyncio.create_task(protocol.send_and_receive(unit_id_2, pdu2))
    deliv_task = asyncio.create_task(deliver_responses())

    res1, res2 = await asyncio.gather(task1, task2)
    await deliv_task

    assert res1 == ("decoded", b"\x03\x05")
    assert res2 == ("decoded", b"\x03\x06")


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


async def test_determine_expected_frame_length__no_data_after_function_code(
    mock_transport: MagicMock,
) -> None:
    """Only unit id + function code buffered: the length byte is missing, so wait for more data."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    protocol._buffer.extend(bytes.fromhex("01 03"))
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


async def test_determine_expected_frame_length__diagnostics_query_data(
    mock_transport: MagicMock,
) -> None:
    """A complete Return Query Data response must frame at its real length, CRC included."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = DiagnosticsQueryDataPDU(b"\xa5\x37")

    # A complete frame: unit and function code, then sub-function, query data and CRC.
    protocol._buffer.extend(bytes.fromhex("01 08 00 00 A5 37 DA 8D"))
    assert protocol._determine_expected_frame_length(pdu) == 8


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


async def test_send_and_receive_timeout_resets_pending_request(
    mock_transport: MagicMock,
) -> None:
    """Test that send_and_receive resets _pending_request and stores timed-out PDU on timeout."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)
    protocol._last_frame_ended_at = time.monotonic() - 10

    pdu = _DummyPDU()
    unit_id = 1

    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu)

    assert protocol._pending_request is None
    assert protocol._timed_out_requests[unit_id] is pdu


async def test_sliding_window_recovers_when_noise_matches_unit_id(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that a stray noise byte matching unit_id slides forward and recovers the valid frame."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # FC 0x03
    unit_id = 1
    response_data = b"\x05"
    correct_payload = bytes([unit_id, pdu.function_code]) + response_data
    correct_response = correct_payload + calculate_crc16(correct_payload)

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Stream contains: 1 noise byte matching unit_id (0x01), followed by the valid response frame
    corrupt_stream = bytes([unit_id, 0x01]) + correct_response

    async def simulate_stream() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(corrupt_stream)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_stream())

    result = await result_task
    await response_task

    assert result[0] == "decoded"


async def test_sliding_window_recovers_when_candidate_fails_crc(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that if a candidate frame fails CRC, sliding window recovers a subsequent valid frame."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    response_data = b"\x05"

    # Candidate 1: has bad CRC
    bad_payload = bytes([unit_id, pdu.function_code]) + response_data
    bad_frame = bad_payload + b"\xff\xff"

    # Candidate 2: valid frame
    good_payload = bytes([unit_id, pdu.function_code]) + response_data
    good_frame = good_payload + calculate_crc16(good_payload)

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_stream() -> None:
        await asyncio.sleep(0.01)
        # Send bad frame followed immediately by good frame
        protocol.data_received(bad_frame + good_frame)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_stream())

    result = await result_task
    await response_task

    assert result[0] == "decoded"


async def test_concurrent_multi_unit_requests_with_sliding_window(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test concurrent requests to different unit IDs with interleaved noise bytes."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu1 = _DummyPDU()
    unit_id_1 = 1
    pdu2 = _DummyPDU()
    unit_id_2 = 2

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    resp1 = bytes([unit_id_1, pdu1.function_code, 0x0A])
    resp1_frame = resp1 + calculate_crc16(resp1)

    resp2 = bytes([unit_id_2, pdu2.function_code, 0x0B])
    resp2_frame = resp2 + calculate_crc16(resp2)

    async def simulate_stream() -> None:
        await asyncio.sleep(0.01)
        # Send noise, then response 1, noise, then response 2
        protocol.data_received(b"\xff\xaa" + resp1_frame)
        await asyncio.sleep(0.01)
        protocol.data_received(b"\xee" + resp2_frame)

    task1 = asyncio.create_task(protocol.send_and_receive(unit_id_1, pdu1))
    task2 = asyncio.create_task(protocol.send_and_receive(unit_id_2, pdu2))
    stream_task = asyncio.create_task(simulate_stream())

    res1, res2 = await asyncio.gather(task1, task2)
    await stream_task

    assert res1 == ("decoded", b"\x03\x0a")
    assert res2 == ("decoded", b"\x03\x0b")


async def test_data_received_fails_pending_request_on_stream_error_when_buffer_exhausted(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that data_received sets exception on _pending_request when CRC or framing errors occur."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
    protocol._pending_request = _PendingRequest(unit_id=unit_id, future=fut, pdu=pdu)

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)

    # Frame with corrupt CRC followed by no more data for unit_id
    bad_frame = bytes([unit_id, 0x03, 0x00, 0xFF, 0xFF])
    protocol.data_received(bad_frame)

    assert fut.done()
    with pytest.raises(CRCError):
        fut.result()


async def test_data_received_stream_error_keeps_pending_when_unit_id_in_buffer(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that data_received does not fail pending request if unit_id is still in buffer."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
    protocol._pending_request = _PendingRequest(unit_id=unit_id, future=fut, pdu=pdu)

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)

    # Corrupt frame followed by 2 bytes starting with unit_id: b"\x01\x03"
    bad_frame = bytes([unit_id, 0x03, 0x00, 0xFF, 0xFF])
    protocol.data_received(bad_frame + bytes([unit_id, 0x03]))

    # Because unit_id 1 is in remaining buffer, future is not failed yet (waits for rest of frame)
    assert not fut.done()
    assert protocol._buffer == bytearray(b"\x01\x03")


async def test_request_aware_framing_rejects_mismatched_function_code(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that request-aware framing detects mismatched function code, discards leading byte and recovers."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # FC 0x03
    unit_id = 1
    response_data = b"\x05"

    # Mismatched reply with FC 0x04 (read input registers) instead of 0x03
    bad_payload = bytes([unit_id, 0x04]) + response_data
    bad_frame = bad_payload + calculate_crc16(bad_payload)

    # Valid reply with FC 0x03
    good_payload = bytes([unit_id, pdu.function_code]) + response_data
    good_frame = good_payload + calculate_crc16(good_payload)

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_stream() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(bad_frame + good_frame)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_stream())

    result = await result_task
    await response_task

    assert result[0] == "decoded"


async def test_large_garbage_burst_resynchronizes(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that a large garbage burst before the response is discarded and the frame still parses."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # FC 0x03
    unit_id = 1
    response_data = b"\x05"

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    good_payload = bytes([unit_id, pdu.function_code]) + response_data
    good_frame = good_payload + calculate_crc16(good_payload)

    # Garbage burst: implausible bytes, then many false frame starts for unit 1 that never pass CRC
    garbage = b"\xff\xfe\xfd" * 500 + bytes([unit_id, pdu.function_code, 0xAA, 0xBB, 0xCC]) * 500

    async def simulate_stream() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(garbage + good_frame)

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    response_task = asyncio.create_task(simulate_stream())

    result = await result_task
    await response_task

    assert result == ("decoded", b"\x03\x05")
    assert len(protocol._buffer) == 0


async def test_large_hostile_garbage_burst_is_bounded(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 64 KiB burst of expected-header false starts must not stall the event loop."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # FC 0x03
    unit_id = 1

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    good_payload = bytes([unit_id, pdu.function_code, 0x05])
    good_frame = good_payload + calculate_crc16(good_payload)

    # False starts with the expected header (01 03) plus embedded exception headers
    # (01 83), so every candidate frames but fails CRC.
    garbage = (b"\x01\x03" * 100 + b"\x01\x83\x00\x00") * 320  # ~64 KiB

    result_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    await asyncio.sleep(0.01)

    started_at = time.monotonic()
    protocol.data_received(garbage)
    elapsed = time.monotonic() - started_at
    # Generous ceiling: the quadratic resync took tens of seconds for this burst.
    assert elapsed < 2.0

    # A real response arriving after the burst must still be delivered.
    protocol.data_received(good_frame)
    result = await result_task
    assert result == ("decoded", b"\x03\x05")


async def test_receive_buffer_is_capped(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The buffer must be trimmed to MAX_RTU_BUFFER_SIZE while the frame length stays undetermined."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
    protocol._pending_request = _PendingRequest(unit_id=unit_id, future=fut, pdu=pdu)

    class UndecidedPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> None:
            return None  # length never determinable: the buffer would otherwise grow forever

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: UndecidedPduClass)

    with caplog.at_level(logging.WARNING, logger="tmodbus.transport.async_rtu"):
        protocol.data_received(bytes([unit_id, pdu.function_code]) * 1500)

    assert len(protocol._buffer) == MAX_RTU_BUFFER_SIZE
    assert any("Receive buffer exceeded" in record.message for record in caplog.records)
    assert not fut.done()


async def test_determine_expected_frame_length_subfunction_pdu(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test _determine_expected_frame_length with subfunction PDU and pending_pdu."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    class DummySubPDU(BaseClientPDU[tuple[str, bytes]]):
        function_code = 0x08  # Diagnostics

        def encode_request(self) -> bytes:
            return b"\x08\x00\x00\x00\x00"

        def decode_response(self, response: bytes) -> tuple[str, bytes]:
            return ("decoded", response)

        @classmethod
        def get_expected_response_data_length(cls, _data: bytes) -> int | None:
            return 2

    monkeypatch.setattr("tmodbus.transport.async_rtu.is_function_code_for_subfunction_pdu", lambda fc: fc == 0x08)
    monkeypatch.setattr("tmodbus.transport.async_rtu.get_subfunction_pdu_class", lambda _fc, _sfc: DummySubPDU)

    pdu = DummySubPDU()
    protocol._buffer = bytearray(b"\x01\x08\x00\x00\x00\x00")
    # Less than 7 bytes for FC 0x08 subfunction PDU (2-byte subfunction code) returns None
    assert protocol._determine_expected_frame_length(pdu) is None

    # With >= 7 bytes returns length (1 + 1 + 2 + 2 = 6)
    protocol._buffer = bytearray(b"\x01\x08\x00\x00\x00\x00\x00")
    assert protocol._determine_expected_frame_length(pdu) == 6


async def test_determine_expected_frame_length_unknown_fc_without_pending_pdu(
    mock_transport: MagicMock,
) -> None:
    """Test _determine_expected_frame_length raises RTUFrameError when FC is unknown and pending_pdu is None."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    protocol._buffer = bytearray(b"\x01\x65\x00\x00")
    with pytest.raises(RTUFrameError, match=r"unsupported function code 0x65"):
        protocol._determine_expected_frame_length(None)


async def test_determine_expected_frame_length_custom_fc_with_pending_pdu(
    mock_transport: MagicMock,
) -> None:
    """Test _determine_expected_frame_length uses type(pending_pdu) when FC is not in standard registry."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    class CustomPDU(BaseClientPDU[tuple[str, bytes]]):
        function_code = 0x65  # Custom FC not in registry

        def encode_request(self) -> bytes:
            return b"\x65\x00"

        def decode_response(self, response: bytes) -> tuple[str, bytes]:
            return ("decoded", response)

        @classmethod
        def get_expected_response_data_length(cls, _data: bytes) -> int | None:
            return 3

    pdu = CustomPDU()
    protocol._buffer = bytearray(b"\x01\x65\x00\x00\x00\x00\x00")
    # 1 (unit) + 1 (fc) + 3 (data) + 2 (crc) = 7
    assert protocol._determine_expected_frame_length(pdu) == 7


def test_modbus_rtu_message_bytes_property() -> None:
    """Test _ModbusRtuMessage bytes property returns full ADU."""
    msg = _ModbusRtuMessage(unit_id=1, pdu_bytes=b"\x03\x02\x00\x01", crc=b"\x12\x34")
    assert msg.bytes == b"\x01\x03\x02\x00\x01\x12\x34"


async def test_send_and_receive_defensive_function_code_validation(
    mock_transport: MagicMock,
) -> None:
    """Test defensive function code validation in send_and_receive when future returns mismatched FC."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # FC 0x03
    unit_id = 1
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def complete_with_mismatch() -> None:
        await asyncio.sleep(0.01)
        # Directly resolve future with mismatched FC (0x04)
        assert protocol._pending_request is not None
        pending = protocol._pending_request
        pending.future.set_result(_ModbusRtuMessage(unit_id=unit_id, pdu_bytes=b"\x04\x00", crc=b"\x00\x00"))

    task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    resolver = asyncio.create_task(complete_with_mismatch())

    with pytest.raises(FunctionCodeError, match=r"Function code mismatch"):
        await task
    await resolver


async def test_delayed_response_after_timeout_is_cleanly_discarded_using_old_pdu(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that when a request times out, a delayed response is framed and discarded using the old PDU."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)

    pdu1 = _DummyPDU()
    unit_id = 1
    response_data = b"\x05"
    delayed_payload = bytes([unit_id, pdu1.function_code]) + response_data
    delayed_response = delayed_payload + calculate_crc16(delayed_payload)

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Step 1: Send request 1, which times out because no response arrived in time
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)

    # Verify that the timed out PDU is preserved
    assert protocol._timed_out_requests[unit_id] is pdu1

    # Step 2: Now the delayed response arrives. It should be framed and discarded cleanly.
    protocol.data_received(delayed_response)

    # Buffer should be completely empty (not containing orphan fragments)
    assert len(protocol._buffer) == 0
    assert unit_id not in protocol._timed_out_requests

    # Step 3: Subsequent request should work cleanly without any stale interference
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    pdu2 = _DummyPDU()
    new_payload = bytes([unit_id, pdu2.function_code, 0x09])
    new_response = new_payload + calculate_crc16(new_payload)

    task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not task.done()
        await asyncio.sleep(0)

    protocol.data_received(new_response)

    result = await task

    assert result == ("decoded", b"\x03\x09")


async def test_try_drain_timed_out_response_branches(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test branch conditions in _try_drain_timed_out_response."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1

    # 1. When buffer is too short to determine length (< 2 bytes) -> returns True (wait)
    protocol._buffer = bytearray(b"\x01")
    assert protocol._try_drain_timed_out_response(unit_id, pdu) is True

    # 2. When _determine_expected_frame_length raises error -> pops and discards leading garbage slice
    protocol._buffer = bytearray(b"\x01\x65\x00\x00")
    protocol._timed_out_requests[unit_id] = pdu
    assert protocol._try_drain_timed_out_response(unit_id, pdu) is False
    assert unit_id not in protocol._timed_out_requests
    assert protocol._buffer == bytearray(b"")  # No plausible start ahead; entire slice discarded

    # 3. When candidate frame has invalid CRC -> discards bad frame up to next plausible start
    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._buffer = bytearray(b"\x01\x03\x05\xff\xff\x01\x03\x05\xaa\xbb")  # bad frame followed by next candidate
    protocol._timed_out_requests[unit_id] = pdu
    assert protocol._try_drain_timed_out_response(unit_id, pdu) is False
    assert protocol._buffer == bytearray(b"\x01\x03\x05\xaa\xbb")  # Resynchronized to next plausible frame start


async def test_delayed_response_drained_in_chunks(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that a delayed response arriving in chunks waits for complete frame and drains it."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    protocol._timed_out_requests[unit_id] = pdu

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 2

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)

    payload = bytes([unit_id, pdu.function_code, 0x00, 0x00])
    frame = payload + calculate_crc16(payload)

    # Chunk 1: first 4 bytes of 6-byte frame -> waits for full frame
    protocol.data_received(frame[:4])
    assert len(protocol._buffer) == 4
    assert unit_id in protocol._timed_out_requests

    # Chunk 2: remaining 2 bytes -> frame completes, CRC passes, buffer drained
    protocol.data_received(frame[4:])
    assert len(protocol._buffer) == 0
    assert unit_id not in protocol._timed_out_requests


async def test_delayed_response_arriving_during_active_request_different_fc(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that when delayed response arrives during active request with different FC, it is drained."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)

    pdu1 = _DummyPDU()
    pdu1.function_code = 0x03

    pdu2 = _DummyPDU()
    pdu2.function_code = 0x06

    unit_id = 1

    class DummyPduClass3:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    class DummyPduClass6:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 2

    def mock_get_pdu_class(fc: int) -> type:
        if fc == 0x03:
            return DummyPduClass3
        if fc == 0x06:
            return DummyPduClass6
        msg = f"Unknown FC {fc}"
        raise ValueError(msg)

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", mock_get_pdu_class)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Step 1: Request 1 times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)

    assert protocol._timed_out_requests[unit_id] is pdu1

    # Step 2: Request 2 is dispatched (FC 0x06) and is active
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    delayed_payload_1 = bytes([unit_id, 0x03, 0xAA])
    delayed_response_1 = delayed_payload_1 + calculate_crc16(delayed_payload_1)

    resp_payload_2 = bytes([unit_id, 0x06, 0x11, 0x22])
    response_2 = resp_payload_2 + calculate_crc16(resp_payload_2)

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    # Deliver late response for request 1 first
    protocol.data_received(delayed_response_1)
    # Active request should still be pending and not failed
    assert protocol._pending_request is not None
    assert not protocol._pending_request.future.done()
    assert unit_id not in protocol._timed_out_requests

    # Now deliver real response for request 2
    protocol.data_received(response_2)

    result = await req2_task

    assert result == ("decoded", b"\x06\x11\x22")
    assert len(protocol._buffer) == 0


async def test_active_request_succeeds_and_clears_stale_timed_out_request(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that a successful response to an active request clears stale timed-out tracking."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.05)
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

    # Request 1 times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)

    assert protocol._timed_out_requests[unit_id] is pdu1

    # Request 2 is sent, and its response arrives directly
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    resp_payload = bytes([unit_id, pdu2.function_code, 0x55])
    response = resp_payload + calculate_crc16(resp_payload)

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    protocol.data_received(response)

    result = await req2_task

    assert result == ("decoded", b"\x03\x55")
    # Verify stale timed-out request tracking was cleared upon successful delivery
    assert unit_id not in protocol._timed_out_requests


async def test_delayed_exception_response_arriving_during_active_request(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that when delayed exception arrives during active request, it is cleanly drained."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)

    pdu1 = _DummyPDU()
    pdu1.function_code = 0x03

    pdu2 = _DummyPDU()
    pdu2.function_code = 0x06

    unit_id = 1

    class DummyPduClass6:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 2

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass6)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Step 1: Request 1 (FC 0x03) times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)

    assert protocol._timed_out_requests[unit_id] is pdu1

    # Step 2: Request 2 (FC 0x06) is sent and active
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    # Late response for Request 1 is an Exception Response (FC 0x83, Exception Code 0x02)
    delayed_exc_payload = bytes([unit_id, 0x83, 0x02])
    delayed_exc_response = delayed_exc_payload + calculate_crc16(delayed_exc_payload)

    resp_payload_2 = bytes([unit_id, 0x06, 0x11, 0x22])
    response_2 = resp_payload_2 + calculate_crc16(resp_payload_2)

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    # Deliver late exception response for request 1
    protocol.data_received(delayed_exc_response)
    # Active request should still be pending (not failed by the delayed exception!)
    assert protocol._pending_request is not None
    assert not protocol._pending_request.future.done()
    assert unit_id not in protocol._timed_out_requests

    # Now deliver real response for request 2
    protocol.data_received(response_2)

    result = await req2_task

    assert result == ("decoded", b"\x06\x11\x22")
    assert len(protocol._buffer) == 0


async def test_delayed_response_in_chunks_during_active_request(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that a delayed response arriving in chunks while a new request is active is waited on and drained."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=0.05)
    protocol.connection_made(mock_transport)

    pdu1 = _DummyPDU()
    pdu1.function_code = 0x03

    pdu2 = _DummyPDU()
    pdu2.function_code = 0x06

    unit_id = 1

    class DummyPduClass3:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 2

    class DummyPduClass6:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 2

    def mock_get_pdu_class(fc: int) -> type:
        if fc == 0x03:
            return DummyPduClass3
        if fc == 0x06:
            return DummyPduClass6
        msg = f"Unknown FC {fc}"
        raise ValueError(msg)

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", mock_get_pdu_class)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Step 1: Request 1 (FC 0x03) times out
    with pytest.raises(TimeoutError):
        await protocol.send_and_receive(unit_id, pdu1)

    assert protocol._timed_out_requests[unit_id] is pdu1

    # Step 2: Request 2 (FC 0x06) is sent and active
    # The tight timeout was only needed to make request 1 time out; request 2
    # must not race the wall clock, so give it a generous timeout.
    protocol.timeout = 10.0

    delayed_payload_1 = bytes([unit_id, 0x03, 0xAA, 0xBB])
    delayed_response_1 = delayed_payload_1 + calculate_crc16(delayed_payload_1)  # 6 bytes

    resp_payload_2 = bytes([unit_id, 0x06, 0x11, 0x22])
    response_2 = resp_payload_2 + calculate_crc16(resp_payload_2)

    req2_task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    while protocol._pending_request is None:
        assert not req2_task.done()
        await asyncio.sleep(0)

    # Deliver chunk 1 of late response (first 4 bytes of 6-byte frame)
    protocol.data_received(delayed_response_1[:4])
    # Buffer has 4 bytes (>= MIN_RTU_RESPONSE_LENGTH), protocol determines frame length is 6 and waits
    assert len(protocol._buffer) == 4
    assert protocol._pending_request is not None
    assert not protocol._pending_request.future.done()
    assert unit_id in protocol._timed_out_requests

    # Deliver chunk 2 of late response (remaining 2 bytes)
    protocol.data_received(delayed_response_1[4:])
    # Now late response is complete and drained
    assert len(protocol._buffer) == 0
    assert protocol._pending_request is not None
    assert not protocol._pending_request.future.done()
    assert unit_id not in protocol._timed_out_requests

    # Now deliver real response for request 2
    protocol.data_received(response_2)

    result = await req2_task

    assert result == ("decoded", b"\x06\x11\x22")
    assert len(protocol._buffer) == 0


async def test_data_received_falls_back_to_pending_request_pdu_when_future_done(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that data_received uses _pending_request.pdu if future is done but _timed_out_requests not yet set."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    pdu.function_code = 0x03
    unit_id = 1

    # Simulate future cancelled/done by asyncio.wait_for timeout before send_and_receive cleans up
    fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
    fut.cancel()
    protocol._pending_request = _PendingRequest(unit_id=unit_id, future=fut, pdu=pdu)

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)

    # Response arrives for the timed-out request
    resp_payload = bytes([unit_id, pdu.function_code, 0x55])
    response = resp_payload + calculate_crc16(resp_payload)

    # When data_received processes this, it falls back to _pending_request.pdu and cleanly drains it
    protocol.data_received(response)
    assert len(protocol._buffer) == 0


async def test_next_request_waits_interframe_delay_after_received_response(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A received response restarts the inter-frame silence clock for the next request."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, interframe_delay=0.1)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    payload = bytes([unit_id, pdu.function_code, 0x05])
    response_adu = payload + calculate_crc16(payload)

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    async def simulate_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(response_adu)

    task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    resp_task = asyncio.create_task(simulate_response())
    await task
    await resp_task

    # data_received stamped the end of the received frame (not the primed value)
    response_received_at = protocol._last_frame_ended_at
    assert time.monotonic() - response_received_at < 5

    write_times: list[float] = []
    request_written = asyncio.Event()

    def record_write(_data: bytes) -> None:
        write_times.append(time.monotonic())
        request_written.set()

    mock_transport.write.side_effect = record_write

    async def simulate_second_response() -> None:
        await request_written.wait()
        protocol.data_received(response_adu)

    task2 = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    resp2_task = asyncio.create_task(simulate_second_response())
    await task2
    await resp2_task

    # The second request must wait out the inter-frame delay measured from the received response
    assert write_times[0] - response_received_at >= 0.1 - 0.001


async def test_cancelled_request_is_tracked_and_delayed_response_drained(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancelled in-flight request is tracked so its delayed response is drained cleanly."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None, timeout=1.0)
    protocol.connection_made(mock_transport)

    pdu1 = _DummyPDU()
    unit_id = 1
    delayed_payload = bytes([unit_id, pdu1.function_code, 0x05])
    delayed_response = delayed_payload + calculate_crc16(delayed_payload)

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Step 1: request is cancelled while in flight
    task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu1))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert protocol._pending_request is None
    assert protocol._timed_out_requests[unit_id] is pdu1

    # Step 2: the delayed response is framed and discarded cleanly
    protocol.data_received(delayed_response)
    assert len(protocol._buffer) == 0
    assert unit_id not in protocol._timed_out_requests

    # Step 3: next request succeeds without stale interference
    pdu2 = _DummyPDU()
    new_payload = bytes([unit_id, pdu2.function_code, 0x09])
    new_response = new_payload + calculate_crc16(new_payload)

    async def simulate_new_response() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(new_response)

    task2 = asyncio.create_task(protocol.send_and_receive(unit_id, pdu2))
    resp_task = asyncio.create_task(simulate_new_response())
    result = await task2
    await resp_task

    assert result == ("decoded", b"\x03\x09")


async def test_resync_skips_matching_unit_id_with_wrong_function_code(
    mock_transport: MagicMock,
) -> None:
    """Test that _resync_discard_length skips embedded unit_id bytes whose following byte is not an expected FC."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # FC 0x03
    unit_id = 1
    protocol._pending_request = _PendingRequest(
        unit_id=unit_id,
        future=asyncio.get_event_loop().create_future(),
        pdu=pdu,
    )

    # Buffer starts with bad frame (unit 1, FC 03), followed by false starts:
    # 01 90 (wrong FC), 01 E1 (wrong FC), 01 00 (wrong FC), 01 0B (wrong FC)
    # and finally a valid frame: 01 03 05 + CRC
    valid_payload = bytes([unit_id, pdu.function_code, 0x05])
    valid_frame = valid_payload + calculate_crc16(valid_payload)

    corrupted_data = (
        bytes([unit_id, pdu.function_code, 0xFF, 0xFF, 0xFF])  # bad frame at index 0 (len 5)
        + bytes([unit_id, 0x90, 0x00, 0x00])  # false start 1 (index 5)
        + bytes([unit_id, 0xE1, 0x03, 0xFF])  # false start 2 (index 9)
        + bytes([unit_id, 0x00, 0x0F, 0x80])  # false start 3 (index 13)
        + bytes([unit_id, 0x0B, 0x00, 0x00])  # false start 4 (index 17)
        + valid_frame  # valid frame starts at index 21
    )

    protocol._buffer = bytearray(corrupted_data)

    # _resync_discard_length should skip all false starts and return index 21 directly
    assert protocol._resync_discard_length() == 21


async def test_extract_log_real_life_resync_recovery(
    mock_transport: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test recovery from real-life scenario in extract.log where payload contains multiple 0x01 bytes."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # FC 0x03
    unit_id = 1

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(begin_bytes: bytes) -> int:
            if not begin_bytes:
                return 1
            # In Modbus Read Holding Registers, first data byte is byte count
            return begin_bytes[0] + 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)
    protocol._last_frame_ended_at = time.monotonic() - 10

    # Valid response frame
    good_payload = bytes([unit_id, pdu.function_code, 0x02, 0x12, 0x34])  # 2 bytes data
    good_frame = good_payload + calculate_crc16(good_payload)

    # Corrupt frame that fails CRC and contains embedded 0x01 bytes with non-matching function codes
    corrupt_candidate = (
        bytes([unit_id, pdu.function_code, 0x08])  # byte count 8 (candidate total length = 1 + 1 + 1 + 8 + 2 = 13)
        + bytes([0x01, 0x90, 0x00, 0x02, 0x01, 0xE1, 0x03, 0xFF])
        + b"\x00\x00"  # invalid CRC
    )

    async def simulate_traffic() -> None:
        await asyncio.sleep(0.01)
        protocol.data_received(corrupt_candidate + good_frame)

    task = asyncio.create_task(protocol.send_and_receive(unit_id, pdu))
    sim_task = asyncio.create_task(simulate_traffic())

    result = await task
    await sim_task

    assert result == ("decoded", b"\x03\x02\x12\x34")
    assert len(protocol._buffer) == 0


async def test_determine_expected_frame_length_exception_fc_mismatch(
    mock_transport: MagicMock,
) -> None:
    """Test that _determine_expected_frame_length rejects exception responses with mismatched function code."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()  # FC 0x03
    # 0x90 is exception response for FC 0x10, not 0x03 (which expects 0x83)
    protocol._buffer = bytearray(b"\x01\x90\x02\x00\x00")

    with pytest.raises(FunctionCodeError, match=r"Function code mismatch for exception response"):
        protocol._determine_expected_frame_length(pdu)


async def test_discard_garbage_data_preserves_trailing_unit_id(
    mock_transport: MagicMock,
) -> None:
    """Test that _discard_garbage_data retains trailing single byte matching unit_id when waiting for next chunk."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    protocol._pending_request = _PendingRequest(
        unit_id=unit_id,
        future=asyncio.get_event_loop().create_future(),
        pdu=pdu,
    )

    # Buffer has garbage ending in 0x01 (unit_id) as the very last byte
    protocol._buffer = bytearray(b"\xff\xfe\xfd\x01")
    protocol._discard_garbage_data()

    # The 3 leading garbage bytes are discarded, but the trailing 0x01 is preserved
    assert protocol._buffer == bytearray(b"\x01")


async def test_discard_garbage_data_when_buffer_starts_with_valid_header(
    mock_transport: MagicMock,
) -> None:
    """Test that _discard_garbage_data does not discard anything when buffer starts with a valid header."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    pdu = _DummyPDU()
    unit_id = 1
    protocol._pending_request = _PendingRequest(
        unit_id=unit_id,
        future=asyncio.get_event_loop().create_future(),
        pdu=pdu,
    )

    protocol._buffer = bytearray(b"\x01\x03\x05\xaa\xbb")
    protocol._discard_garbage_data()

    assert protocol._buffer == bytearray(b"\x01\x03\x05\xaa\xbb")


async def test_send_and_receive_no_response_pdu(
    mock_transport: MagicMock,
) -> None:
    """Test send_and_receive when PDU expects_response is False."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
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


def test_rtu_protocol_fc08_partial_buffer(mock_transport: MagicMock) -> None:
    """Test data_received on ModbusRtuProtocol with partial FC08 Diagnostics frame."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)

    # 0x01 address, 0x08 FC, 0x00 sub-func byte 1 (missing 2nd sub-func byte, length < 7)
    protocol.data_received(b"\x01\x08\x00")
    assert protocol._pending_request is None

    # Test buffer >= 7 bytes for FC08 Diagnostics frame parsing
    protocol._buffer = bytearray(b"\x01\x08\x00\x00\x00")
    assert protocol._determine_expected_frame_length() is None
    # address(1) + fc(1) + sub-function(2) + query data(2) + crc(2)
    protocol._buffer = bytearray(b"\x01\x08\x00\x00\x00\x00\x00")
    assert protocol._determine_expected_frame_length() == 8


class _FixedLengthPDU(BaseClientPDU[bytes]):
    """PDU declaring a fixed RTU request length, with a caller-controlled payload."""

    function_code = 0x08
    rtu_request_data_length = 4

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def encode_request(self) -> bytes:
        return bytes([self.function_code]) + self.payload

    def decode_response(self, response: bytes) -> bytes:
        return response


def test_validate_rtu_request_length__no_declared_length() -> None:
    """A PDU without a fixed request length is left alone."""
    pdu = _DummyPDU()
    assert pdu.rtu_request_data_length is None
    _validate_rtu_request_length(pdu, pdu.encode_request())


def test_validate_rtu_request_length__matching() -> None:
    """A request encoding to its declared length is accepted."""
    pdu = _FixedLengthPDU(b"\x00\x00\xa5\x37")
    _validate_rtu_request_length(pdu, pdu.encode_request())


def test_validate_rtu_request_length__mismatch() -> None:
    """A request that cannot be framed is rejected, naming both lengths."""
    pdu = _FixedLengthPDU(b"\x00\x00\xa5\x37\x11\x22")
    with pytest.raises(InvalidRequestError, match="encodes 6 data bytes but declares 4"):
        _validate_rtu_request_length(pdu, pdu.encode_request())


async def test_send_and_receive_rejects_unframable_request(mock_transport: MagicMock) -> None:
    """An un-framable request is refused before anything reaches the wire."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    protocol.connection_made(mock_transport)
    mock_transport.write.reset_mock()

    with pytest.raises(InvalidRequestError, match="cannot be framed over RTU"):
        await protocol.send_and_receive(1, _FixedLengthPDU(b"\x00\x00\xa5\x37\x11\x22"))

    mock_transport.write.assert_not_called()
