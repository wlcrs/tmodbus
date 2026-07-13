"""Tests for tmodbus/server/async_rtu_over_tcp.py."""

import asyncio
import contextlib
from unittest.mock import patch

import pytest
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteMultipleRegistersPDU
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.server import AsyncRtuOverTcpServer, ModbusRequestRouter
from tmodbus.utils.crc import calculate_crc16, validate_crc16


@pytest.fixture
async def rtu_over_tcp_server() -> AsyncRtuOverTcpServer:
    """Fixture to start a Modbus RTU-over-TCP server on a free local port."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x1111, 0x2222]

    # Use port=0 so OS dynamically allocates a free port
    server = AsyncRtuOverTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    yield server
    await server.stop()


def get_server_port(server: AsyncRtuOverTcpServer) -> int:
    """Get the dynamic port allocated to the RTU-over-TCP server."""
    assert server._server is not None
    sockets = server._server.sockets
    assert sockets is not None
    assert len(sockets) > 0
    return sockets[0].getsockname()[1]


async def test_rtu_over_tcp_server_happy_path(rtu_over_tcp_server: AsyncRtuOverTcpServer) -> None:
    """Test successful request/response transaction on the RTU-over-TCP server."""
    port = get_server_port(rtu_over_tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # Build Read Holding Registers request: unit_id=1, function_code=3, start_address=0, quantity=2
        pdu = b"\x01\x03\x00\x00\x00\x02"
        crc = calculate_crc16(pdu)
        writer.write(pdu + crc)
        await writer.drain()

        # Read response. RTU response size for 2 registers is:
        # unit_id(1) + fc(1) + byte_count(1) + data(4) + crc(2) = 9 bytes
        resp = await reader.readexactly(9)
        assert resp[0] == 1
        assert resp[1] == 3
        assert resp[2] == 4  # byte count
        assert resp[3:7] == b"\x11\x11\x22\x22"
        assert validate_crc16(resp)

    finally:
        writer.close()
        await writer.wait_closed()


async def test_rtu_over_tcp_server_invalid_crc(rtu_over_tcp_server: AsyncRtuOverTcpServer) -> None:
    """Test that a frame with an invalid CRC is ignored and connection remains open."""
    port = get_server_port(rtu_over_tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # Send frame with invalid CRC (b"\x00\x00")
        pdu = b"\x01\x03\x00\x00\x00\x02"
        frame = pdu + b"\x00\x00"
        with patch("tmodbus.server.async_rtu_over_tcp.log_raw_traffic") as mock_log:
            writer.write(frame)
            await writer.drain()
            await asyncio.sleep(0.05)
            mock_log.assert_any_call("recv", frame, is_error=True)

        # Send a valid frame right after to verify connection remains open and functional
        pdu2 = b"\x01\x03\x00\x00\x00\x02"
        crc2 = calculate_crc16(pdu2)
        with patch("tmodbus.server.async_rtu_over_tcp.log_raw_traffic") as mock_log:
            writer.write(pdu2 + crc2)
            await writer.drain()
            resp = await reader.readexactly(9)
            mock_log.assert_any_call("recv", pdu2 + crc2, is_error=False)

        assert resp[0] == 1
        assert resp[1] == 3
        assert resp[3:7] == b"\x11\x11\x22\x22"

    finally:
        writer.close()
        await writer.wait_closed()


async def test_rtu_over_tcp_server_unsupported_function_code(rtu_over_tcp_server: AsyncRtuOverTcpServer) -> None:
    """Test that connection is closed immediately if function code is unsupported (desynchronization fix)."""
    port = get_server_port(rtu_over_tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # Function code 0x99 is unsupported
        pdu = b"\x01\x99\x00\x00\x00\x02"
        crc = calculate_crc16(pdu)
        frame = pdu + crc
        with patch("tmodbus.server.async_rtu_over_tcp.log_raw_traffic") as mock_log:
            writer.write(frame)
            await writer.drain()
            # Server should disconnect immediately to prevent stream desynchronization
            data = await reader.read(100)
            mock_log.assert_any_call("recv", frame, is_error=True)
            assert len(data) == 0  # EOF received

    finally:
        writer.close()
        await writer.wait_closed()


async def test_rtu_over_tcp_server_frame_too_large(rtu_over_tcp_server: AsyncRtuOverTcpServer) -> None:
    """Test that connection is closed immediately if expected frame size is too large (desynchronization fix)."""
    port = get_server_port(rtu_over_tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # Function code 16 (Write Multiple Registers): start_addr=0, quantity=125 registers (250 bytes payload)
        # This will be ok, but let's send quantity=250 (500 bytes payload) to exceed MAX_RTU_FRAME_SIZE (256)
        pdu = b"\x01\x10\x00\x00\x00\xfa\xfb"  # quantity=250, byte_count=251
        with patch("tmodbus.server.async_rtu_over_tcp.log_raw_traffic") as mock_log:
            writer.write(pdu)
            await writer.drain()
            # Server should disconnect immediately
            data = await reader.read(100)
            mock_log.assert_any_call("recv", pdu, is_error=True)
            assert len(data) == 0  # EOF received

    finally:
        writer.close()
        await writer.wait_closed()


async def test_rtu_over_tcp_server_raw_traffic_logging(rtu_over_tcp_server: AsyncRtuOverTcpServer) -> None:
    """Test that RTU-over-TCP server logs raw traffic with is_error=True on errors."""
    port = get_server_port(rtu_over_tcp_server)

    with patch("tmodbus.server.async_rtu_over_tcp.log_raw_traffic") as mock_log:
        # 1. Invalid frame length (ValueError in parsing)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            pdu = b"\x01\x10\x00\x00\x00\xfa\xfb"
            writer.write(pdu)
            await writer.drain()
            await reader.read(10)
        finally:
            writer.close()
            await writer.wait_closed()

        mock_log.assert_any_call("recv", pdu, is_error=True)

        # 2. Bad CRC
        mock_log.reset_mock()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            pdu_bad_crc = b"\x01\x03\x00\x00\x00\x01\x00\x00"  # Incorrect CRC
            writer.write(pdu_bad_crc)
            await writer.drain()
            await asyncio.sleep(0.05)
        finally:
            writer.close()
            await writer.wait_closed()

        mock_log.assert_any_call("recv", pdu_bad_crc, is_error=True)

        # 3. Residual bytes on client disconnect
        mock_log.reset_mock()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"\x01\x03")  # Incomplete frame
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

        await asyncio.sleep(0.05)  # allow server task to process the disconnect
        mock_log.assert_any_call("recv", b"\x01\x03", is_error=True)


async def test_rtu_over_tcp_server_double_stop_and_serve_forever() -> None:
    """Test serve_forever and double stop on AsyncRtuOverTcpServer."""
    router = ModbusRequestRouter()
    rtu_tcp = AsyncRtuOverTcpServer(host="127.0.0.1", port=0, handler=router)
    await rtu_tcp.stop()  # Stop before starting
    task = asyncio.create_task(rtu_tcp.serve_forever())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await rtu_tcp.stop()  # Second stop


async def test_rtu_over_tcp_server_edge_cases() -> None:  # noqa: PLR0915
    """Cover edge cases in AsyncRtuOverTcpServer."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [1]

    @router.register(WriteMultipleRegistersPDU)
    async def handle_write_multiple(_unit_id: int, _request: WriteMultipleRegistersPDU) -> int:
        return 1

    server = AsyncRtuOverTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()

    port = get_server_port(server)

    # 1. Fragmented frame: send 2 bytes (returns None), then 5 bytes (len < expected_total_len)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"\x01\x03")
        await writer.drain()
        await asyncio.sleep(0.05)

        writer.write(b"\x00\x00\x00")
        await writer.drain()
        await asyncio.sleep(0.05)

        pdu = b"\x01\x03\x00\x00\x00\x01"
        writer.write(b"\x01" + calculate_crc16(pdu))
        await writer.drain()

        # Should receive response
        resp = await reader.readexactly(7)
        assert resp[0] == 1
        assert resp[1] == 3
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    # 2. Fragmented Write Multiple Registers (FC 16) request: send 5 bytes (length < 5 for data), then the rest
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"\x01\x10\x00\x00\x00")
        await writer.drain()
        await asyncio.sleep(0.05)

        pdu_regs = b"\x01\x10\x00\x00\x00\x01\x02\x00\x01"
        writer.write(pdu_regs[5:] + calculate_crc16(pdu_regs))
        await writer.drain()

        # Should receive response: Address (2) + Quantity (2)
        resp = await reader.readexactly(8)  # unit(1) + fc(1) + addr(2) + qty(2) + crc(2)
        assert resp[1] == 16
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    # PDU class resolution returning None (not enough data to resolve sub-function)
    # Send only unit_id=1, fc=43 (0x2B) without sub-function code
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"\x01\x2b")
        await writer.drain()
        await asyncio.sleep(0.05)

        # Send valid sub-function next to verify it recovers after getting more bytes
        # fc=43, sub=14 (0x0E), mei=1, obj=0
        pdu_sub = b"\x01\x2b\x0e\x01\x00"
        writer.write(b"\x0e\x01\x00" + calculate_crc16(pdu_sub))
        await writer.drain()
        # Should get response (which is EOF / disconnect due to client-only PDU class)
        resp = await reader.read(100)
        assert len(resp) == 0
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    # Invalid sub-function code (fc=43, sub=0) -> disconnects client
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        pdu_bad_sub = b"\x01\x2b\x00\x01\x00"
        writer.write(pdu_bad_sub + calculate_crc16(pdu_bad_sub))
        await writer.drain()
        data = await reader.read(100)
        assert len(data) == 0  # Disconnected
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    # Invalid request PDU parameter: quantity = 0 (raises InvalidRequestError) -> responds with exception
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        pdu_bad_param = b"\x01\x03\x00\x00\x00\x00"
        writer.write(pdu_bad_param + calculate_crc16(pdu_bad_param))
        await writer.drain()
        resp = await reader.readexactly(5)  # unit(1)+fc|0x80(1)+err(1)+crc(2)
        assert resp[1] == 0x83
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    # Non-server PDU class check -> disconnects client
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:

        class DummyClientOnlyPDU(BaseClientPDU[None]):
            function_code = 0x03

        with patch("tmodbus.server.async_rtu_over_tcp.get_pdu_class", return_value=DummyClientOnlyPDU):
            writer.write(b"\x01\x03\x00\x00\x00\x01\x00\x00")
            await writer.drain()
            await asyncio.sleep(0.05)

        data = await reader.read(100)
        assert len(data) == 0
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    # Reconnect to test client handler exception -> disconnects client
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        with patch.object(server, "_process_next_frame", side_effect=RuntimeError("Generic Exception")):
            writer.write(b"\x01\x03\x00\x00\x00\x02\x00\x00")
            await writer.drain()
            data = await reader.read(100)
            assert len(data) == 0
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    # Exceed expected total size > MAX_RTU_FRAME_SIZE -> disconnects client
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        # byte_count = 250 (so data size 255, total frame 259 > 256)
        writer.write(b"\x01\x10\x00\x00\x00\x00\xfa")
        await writer.drain()
        data = await reader.read(100)
        assert len(data) == 0
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    await server.stop()


async def test_rtu_over_tcp_server_unregistered_unit_id() -> None:
    """Test that RTU-over-TCP server returns configured exception response for unregistered unit ID."""
    router = ModbusRequestRouter()

    # Register only for unit_id=1
    @router.register(ReadHoldingRegistersPDU, unit_id=1)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x1234]

    server = AsyncRtuOverTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()

    try:
        port = get_server_port(server)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        try:
            # Request to unregistered unit_id=2 (RTU framing)
            pdu = b"\x02\x03\x00\x00\x00\x01"
            frame = bytearray(pdu) + calculate_crc16(pdu)
            writer.write(frame)
            await writer.drain()

            resp = await reader.readexactly(5)  # unit(1) + fc|0x80(1) + err(1) + crc(2)
            assert resp[0] == 2
            assert resp[1] == 0x83
            # Default is 0x0B
            assert resp[2] == 0x0B

        finally:
            writer.close()
            await writer.wait_closed()

    finally:
        await server.stop()


async def test_rtu_over_tcp_server_configurable_exception_code() -> None:
    """Test that RTU-over-TCP server unregistered unit ID exception code is configurable."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU, unit_id=1)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x1234]

    server = AsyncRtuOverTcpServer(
        host="127.0.0.1",
        port=0,
        handler=router,
        unregistered_unit_id_exception_code=0x0A,  # GATEWAY_PATH_UNAVAILABLE
    )
    await server.start()

    try:
        port = get_server_port(server)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        try:
            # Request to unregistered unit_id=2 (RTU framing)
            pdu = b"\x02\x03\x00\x00\x00\x01"
            frame = bytearray(pdu) + calculate_crc16(pdu)
            writer.write(frame)
            await writer.drain()

            resp = await reader.readexactly(5)
            assert resp[0] == 2
            assert resp[1] == 0x83
            assert resp[2] == 0x0A

        finally:
            writer.close()
            await writer.wait_closed()

    finally:
        await server.stop()
