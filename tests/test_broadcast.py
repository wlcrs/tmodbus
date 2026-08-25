"""Comprehensive tests for Modbus broadcast request support."""

import asyncio
from typing import Any

import pytest
from tmodbus.client import AsyncModbusClient
from tmodbus.const import BROADCAST_UNIT_ID
from tmodbus.exceptions import InvalidRequestError
from tmodbus.pdu import (
    BaseClientPDU,
    DiagnosticsRestartCommunicationsOptionPDU,
    FileRecord,
    FileRecordRequest,
    MaskWriteRegisterPDU,
    ReadCoilsPDU,
    ReadDeviceIdentificationPDU,
    ReadDiscreteInputsPDU,
    ReadExceptionStatusPDU,
    ReadFifoQueuePDU,
    ReadFileRecordPDU,
    ReadHoldingRegistersPDU,
    ReadInputRegistersPDU,
    ReadWriteMultipleRegistersPDU,
    ReportServerIdPDU,
    WriteFileRecordPDU,
    WriteMultipleCoilsPDU,
    WriteMultipleRegistersPDU,
    WriteSingleCoilPDU,
    WriteSingleRegisterPDU,
)
from tmodbus.pdu.holding_registers import RawReadHoldingRegistersPDU, RawWriteMultipleRegistersPDU
from tmodbus.server.async_ascii import AsyncAsciiServer
from tmodbus.server.async_rtu import AsyncRtuServer
from tmodbus.server.async_rtu_over_tcp import AsyncRtuOverTcpServer
from tmodbus.server.handler import ModbusRequestRouter, handle_modbus_request
from tmodbus.transport.async_ascii import ModbusAsciiProtocol
from tmodbus.transport.async_rtu import ModbusRtuProtocol
from tmodbus.utils.crc import calculate_crc16
from tmodbus.utils.lrc import calculate_lrc


class MockWriteTransport(asyncio.WriteTransport):
    """Mock write transport for protocol testing."""

    def __init__(self) -> None:
        """Initialize mock write transport."""
        super().__init__()
        self.written: list[bytes] = []
        self._closing = False

    def write(self, data: bytes | bytearray | memoryview) -> None:
        """Write data to the transport."""
        self.written.append(bytes(data))

    def is_closing(self) -> bool:
        """Check if the transport is closing."""
        return self._closing

    def close(self) -> None:
        """Close the transport."""
        self._closing = True


class MockStreamWriter:
    """Mock asyncio.StreamWriter for server testing."""

    def __init__(self) -> None:
        """Initialize mock stream writer."""
        self.written: list[bytes] = []

    def write(self, data: bytes) -> None:
        """Write data to the stream writer."""
        self.written.append(bytes(data))

    async def drain(self) -> None:
        """Drain the stream writer."""


# ============================================================================
# PDU Broadcast Tests
# ============================================================================


def test_pdu_write_single_coil_broadcast() -> None:
    """Test get_broadcast_response for WriteSingleCoilPDU with True and False values."""
    pdu_true = WriteSingleCoilPDU(0, True)  # noqa: FBT003
    assert pdu_true.get_broadcast_response() is True

    pdu_false = WriteSingleCoilPDU(0, False)  # noqa: FBT003
    assert pdu_false.get_broadcast_response() is False


def test_pdu_write_multiple_coils_broadcast() -> None:
    """Test get_broadcast_response for WriteMultipleCoilsPDU."""
    pdu = WriteMultipleCoilsPDU(0, [True, False, True])
    assert pdu.get_broadcast_response() == 3


def test_pdu_write_single_register_broadcast() -> None:
    """Test get_broadcast_response for WriteSingleRegisterPDU."""
    pdu = WriteSingleRegisterPDU(0, 12345)
    assert pdu.get_broadcast_response() == 12345

    pdu_zero = WriteSingleRegisterPDU(0, 0)
    assert pdu_zero.get_broadcast_response() == 0


def test_pdu_write_multiple_registers_broadcast() -> None:
    """Test get_broadcast_response for WriteMultipleRegistersPDU."""
    pdu = WriteMultipleRegistersPDU(0, [1, 2, 3, 4])
    assert pdu.get_broadcast_response() == 4


def test_pdu_raw_write_multiple_registers_broadcast() -> None:
    """Test get_broadcast_response for RawWriteMultipleRegistersPDU."""
    pdu = RawWriteMultipleRegistersPDU(0, b"\x00\x01\x00\x02")
    assert pdu.get_broadcast_response() == 2


def test_pdu_mask_write_register_broadcast() -> None:
    """Test get_broadcast_response for MaskWriteRegisterPDU."""
    pdu = MaskWriteRegisterPDU(0, 0x00FF, 0xFF00)
    assert pdu.get_broadcast_response() == (0x00FF, 0xFF00)


def test_pdu_write_file_record_broadcast() -> None:
    """Test get_broadcast_response for WriteFileRecordPDU."""
    records = [FileRecord(1, 2, b"\x00\x01\x00\x02")]
    pdu = WriteFileRecordPDU(records)
    assert pdu.get_broadcast_response() == records


def test_pdu_restart_communications_option_broadcast() -> None:
    """Test get_broadcast_response for DiagnosticsRestartCommunicationsOptionPDU."""
    pdu = DiagnosticsRestartCommunicationsOptionPDU()
    assert pdu.get_broadcast_response() is False

    pdu_clear = DiagnosticsRestartCommunicationsOptionPDU(clear_event_log=True)
    assert pdu_clear.get_broadcast_response() is True


def test_non_broadcastable_pdus_raise_error() -> None:
    """Test that all non-broadcastable PDUs raise InvalidRequestError."""
    read_pdus: list[BaseClientPDU[Any]] = [
        ReadCoilsPDU(0, 1),
        ReadDiscreteInputsPDU(0, 1),
        ReadHoldingRegistersPDU(0, 1),
        RawReadHoldingRegistersPDU(0, 1),
        ReadInputRegistersPDU(0, 1),
        ReadFileRecordPDU([FileRecordRequest(1, 0, 1)]),
        ReadFifoQueuePDU(0),
        ReadDeviceIdentificationPDU(1, 0),
        ReportServerIdPDU(),
        ReadExceptionStatusPDU(),
        ReadWriteMultipleRegistersPDU(0, 1, 0, [100]),
    ]
    for pdu in read_pdus:
        with pytest.raises(InvalidRequestError, match="does not support broadcasting"):
            pdu.get_broadcast_response()


# ============================================================================
# Client Transport Broadcast Tests
# ============================================================================


@pytest.mark.asyncio
async def test_rtu_client_broadcast() -> None:
    """Test ModbusRtuProtocol broadcast request execution."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    mock_transport = MockWriteTransport()
    protocol.connection_made(mock_transport)

    # Test writing False (falsy value check)
    pdu_false = WriteSingleCoilPDU(10, False)  # noqa: FBT003
    res_false = await protocol.send_and_receive(BROADCAST_UNIT_ID, pdu_false)
    assert res_false is False
    assert len(mock_transport.written) == 1

    # Test writing True
    pdu_true = WriteSingleCoilPDU(10, True)  # noqa: FBT003
    res_true = await protocol.send_and_receive(BROADCAST_UNIT_ID, pdu_true)
    assert res_true is True
    assert len(mock_transport.written) == 2


@pytest.mark.asyncio
async def test_ascii_client_broadcast() -> None:
    """Test ModbusAsciiProtocol broadcast request execution."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None)
    mock_transport = MockWriteTransport()
    protocol.connection_made(mock_transport)

    pdu = WriteSingleRegisterPDU(100, 42)
    res = await protocol.send_and_receive(BROADCAST_UNIT_ID, pdu)
    assert res == 42
    assert len(mock_transport.written) == 1


@pytest.mark.asyncio
async def test_rtu_client_broadcast_restart_communications() -> None:
    """Test broadcasting Restart Communications Option over RTU writes correct bytes without reading."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    mock_transport = MockWriteTransport()
    protocol.connection_made(mock_transport)

    pdu = DiagnosticsRestartCommunicationsOptionPDU()
    res = await protocol.send_and_receive(BROADCAST_UNIT_ID, pdu)
    assert res is False
    frame_prefix = bytes([0x00, 0x08, 0x00, 0x01, 0x00, 0x00])
    assert mock_transport.written == [frame_prefix + calculate_crc16(frame_prefix)]

    pdu_clear = DiagnosticsRestartCommunicationsOptionPDU(clear_event_log=True)
    res_clear = await protocol.send_and_receive(BROADCAST_UNIT_ID, pdu_clear)
    assert res_clear is True
    frame_prefix_clear = bytes([0x00, 0x08, 0x00, 0x01, 0xFF, 0x00])
    assert mock_transport.written[1] == frame_prefix_clear + calculate_crc16(frame_prefix_clear)


@pytest.mark.asyncio
async def test_ascii_client_broadcast_restart_communications() -> None:
    """Test broadcasting Restart Communications Option over ASCII writes correct bytes without reading."""
    protocol = ModbusAsciiProtocol(on_connection_lost=lambda _: None)
    mock_transport = MockWriteTransport()
    protocol.connection_made(mock_transport)

    pdu = DiagnosticsRestartCommunicationsOptionPDU(clear_event_log=True)
    res = await protocol.send_and_receive(BROADCAST_UNIT_ID, pdu)
    assert res is True
    bin_data = bytes([0x00, 0x08, 0x00, 0x01, 0xFF, 0x00])
    expected_frame = b":" + (bin_data + bytes([calculate_lrc(bin_data)])).hex().upper().encode("ascii") + b"\r\n"
    assert mock_transport.written == [expected_frame]


@pytest.mark.asyncio
async def test_async_client_broadcast_execution() -> None:
    """Test AsyncModbusClient executing broadcast requests over serial RTU transport."""
    protocol = ModbusRtuProtocol(on_connection_lost=lambda _: None)
    mock_transport = MockWriteTransport()
    protocol.connection_made(mock_transport)

    class FakeAsyncTransport:
        def is_open(self) -> bool:
            return True

        async def send_and_receive(self, unit_id: int, pdu: Any) -> Any:
            return await protocol.send_and_receive(unit_id, pdu)

    client = AsyncModbusClient(FakeAsyncTransport(), unit_id=BROADCAST_UNIT_ID)  # type: ignore[arg-type]
    res = await client.write_single_coil(0, False)  # noqa: FBT003
    assert res is False

    res_restart = await client.diag_restart_communications_option(clear_event_log=True)
    assert res_restart is True


# ============================================================================
# Server Broadcast Execution & Response Suppression Tests
# ============================================================================


@pytest.mark.asyncio
async def test_server_broadcast_handler_invocation() -> None:
    """Test that handle_modbus_request processes broadcast requests for unit ID 0."""
    executed = []

    router = ModbusRequestRouter()

    @router.register(WriteSingleRegisterPDU)
    async def handle_write_register(unit_id: int, request: WriteSingleRegisterPDU) -> int:
        executed.append((unit_id, request.address, request.value))
        return request.value

    pdu = WriteSingleRegisterPDU(10, 555)
    res_bytes = await handle_modbus_request(BROADCAST_UNIT_ID, pdu, router)
    assert len(executed) == 1
    assert executed[0] == (0, 10, 555)
    assert res_bytes == pdu.encode_response(555)


@pytest.mark.asyncio
async def test_rtu_server_broadcast_response_suppressed() -> None:
    """Test AsyncRtuServer suppresses sending response frame when unit_id is 0."""
    executed = []

    router = ModbusRequestRouter()

    @router.register(WriteSingleRegisterPDU)
    async def handle_write(unit_id: int, request: WriteSingleRegisterPDU) -> int:
        executed.append((unit_id, request.value))
        return request.value

    server = AsyncRtuServer(port="dummy", handler=router)
    server._inter_frame_silence = 0.0

    # Build RTU frame for unit 0, WriteSingleRegister (FC 0x06, addr 0x0001, val 0x0002)
    pdu_bytes = bytes([0x06, 0x00, 0x01, 0x00, 0x02])
    frame = bytearray([0x00]) + pdu_bytes
    crc = calculate_crc16(bytes(frame))
    frame.extend(crc)

    mock_writer = MockWriteTransport()
    server._writer = mock_writer  # type: ignore[assignment]

    status = await server._handle_frame(bytes(frame))
    assert status == "success"
    assert len(executed) == 1
    assert executed[0] == (0, 2)
    # Output frame suppressed for unit_id 0
    assert len(mock_writer.written) == 0


@pytest.mark.asyncio
async def test_ascii_server_broadcast_response_suppressed() -> None:
    """Test AsyncAsciiServer suppresses sending response frame when unit_id is 0."""
    executed = []

    router = ModbusRequestRouter()

    @router.register(WriteSingleCoilPDU)
    async def handle_write(unit_id: int, request: WriteSingleCoilPDU) -> bool:
        executed.append((unit_id, request.value))
        return request.value

    server = AsyncAsciiServer(port="dummy", handler=router)

    # Build ASCII frame for unit 0, WriteSingleCoil (FC 0x05, addr 0, val FF00)
    bin_data = bytes([0x00, 0x05, 0x00, 0x00, 0xFF, 0x00])
    lrc = calculate_lrc(bin_data)
    ascii_hex = (bin_data + bytes([lrc])).hex().upper().encode("ascii")
    ascii_frame = b":" + ascii_hex + b"\r\n"

    mock_writer = MockWriteTransport()
    server._writer = mock_writer  # type: ignore[assignment]

    status = await server._process_next_frame(ascii_frame)
    assert status == "success"
    assert len(executed) == 1
    assert len(mock_writer.written) == 0


@pytest.mark.asyncio
async def test_rtu_over_tcp_server_broadcast_response_suppressed() -> None:
    """Test AsyncRtuOverTcpServer suppresses sending response frame when unit_id is 0."""
    executed = []

    router = ModbusRequestRouter()

    @router.register(WriteSingleRegisterPDU)
    async def handle_write(unit_id: int, request: WriteSingleRegisterPDU) -> int:
        executed.append((unit_id, request.value))
        return request.value

    server = AsyncRtuOverTcpServer(host="localhost", port=502, handler=router)

    pdu_bytes = bytes([0x06, 0x00, 0x01, 0x00, 0x02])
    frame = bytearray([0x00]) + pdu_bytes
    crc = calculate_crc16(bytes(frame))
    frame.extend(crc)

    mock_writer = MockStreamWriter()
    status = await server._handle_frame(bytes(frame), ("127.0.0.1", 12345), mock_writer)  # type: ignore[arg-type]
    assert status is True
    assert len(executed) == 1
    assert len(mock_writer.written) == 0


def _build_broadcast_decode_error_pdu() -> bytes:
    """Return PDU bytes that fail decoding: ReadHoldingRegisters (FC 0x03) with quantity 0."""
    return bytes([0x03, 0x00, 0x00, 0x00, 0x00])


def _make_router() -> ModbusRequestRouter:
    """Return a router that supports all unit IDs."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
        return [0] * request.quantity

    return router


@pytest.mark.asyncio
async def test_rtu_server_broadcast_decode_error_suppressed() -> None:
    """Test AsyncRtuServer does not send an exception response for a malformed broadcast frame."""
    server = AsyncRtuServer(port="dummy", handler=_make_router())
    server._inter_frame_silence = 0.0

    frame = bytearray([0x00]) + _build_broadcast_decode_error_pdu()
    frame.extend(calculate_crc16(bytes(frame)))

    mock_writer = MockWriteTransport()
    server._writer = mock_writer  # type: ignore[assignment]

    status = await server._handle_frame(bytes(frame))
    assert status == "error"
    assert len(mock_writer.written) == 0


@pytest.mark.asyncio
async def test_ascii_server_broadcast_decode_error_suppressed() -> None:
    """Test AsyncAsciiServer does not send an exception response for a malformed broadcast frame."""
    server = AsyncAsciiServer(port="dummy", handler=_make_router())

    bin_data = bytes([0x00]) + _build_broadcast_decode_error_pdu()
    ascii_hex = (bin_data + bytes([calculate_lrc(bin_data)])).hex().upper().encode("ascii")
    ascii_frame = b":" + ascii_hex + b"\r\n"

    mock_writer = MockWriteTransport()
    server._writer = mock_writer  # type: ignore[assignment]

    status = await server._process_next_frame(ascii_frame)
    assert status == "error"
    assert len(mock_writer.written) == 0


@pytest.mark.asyncio
async def test_rtu_over_tcp_server_broadcast_decode_error_suppressed() -> None:
    """Test AsyncRtuOverTcpServer does not send an exception response for a malformed broadcast frame."""
    server = AsyncRtuOverTcpServer(host="localhost", port=502, handler=_make_router())

    frame = bytearray([0x00]) + _build_broadcast_decode_error_pdu()
    frame.extend(calculate_crc16(bytes(frame)))

    mock_writer = MockStreamWriter()
    status = await server._handle_frame(bytes(frame), ("127.0.0.1", 12345), mock_writer)  # type: ignore[arg-type]
    assert status is False
    assert len(mock_writer.written) == 0


@pytest.mark.asyncio
async def test_rtu_over_tcp_server_broadcast_unregistered_unit_suppressed() -> None:
    """Test AsyncRtuOverTcpServer does not answer a broadcast frame when unit ID 0 is not registered."""
    router = ModbusRequestRouter()

    @router.register(WriteSingleRegisterPDU, unit_id=5)
    async def handle_write(_unit_id: int, request: WriteSingleRegisterPDU) -> int:
        return request.value

    server = AsyncRtuOverTcpServer(host="localhost", port=502, handler=router)

    pdu_bytes = bytes([0x06, 0x00, 0x01, 0x00, 0x02])
    frame = bytearray([0x00]) + pdu_bytes
    frame.extend(calculate_crc16(bytes(frame)))

    mock_writer = MockStreamWriter()
    status = await server._handle_frame(bytes(frame), ("127.0.0.1", 12345), mock_writer)  # type: ignore[arg-type]
    assert status is False
    assert len(mock_writer.written) == 0
