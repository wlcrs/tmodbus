"""Tests for tmodbus/server/async_tcp.py."""

import asyncio
import contextlib
import struct
from collections.abc import AsyncIterator
from unittest.mock import patch

import pytest
from tmodbus.pdu import ReadHoldingRegistersPDU
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.server import AsyncTcpServer, ModbusRequestRouter


@pytest.fixture
async def tcp_server() -> AsyncIterator[AsyncTcpServer]:
    """Fixture to start a Modbus TCP server on a free local port."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x1234, 0x5678]

    # Use port=0 so OS dynamically allocates a free port
    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    yield server
    await server.stop()


def get_server_port(server: AsyncTcpServer) -> int:
    """Get the dynamic port allocated to the TCP server."""
    assert server._server is not None
    sockets = server._server.sockets
    assert sockets is not None
    assert len(sockets) > 0
    addr = sockets[0].getsockname()
    assert isinstance(addr, tuple)
    return int(addr[1])


async def test_tcp_server_happy_path(tcp_server: AsyncTcpServer) -> None:
    """Test successful request/response transaction on the TCP server."""
    port = get_server_port(tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # Build Read Holding Registers request: transaction_id=1, protocol_id=0, length=6, unit_id=1
        # PDU: function_code=3, start_address=0, quantity=2
        mbap = struct.pack(">HHHB", 1, 0, 6, 1)
        pdu = b"\x03\x00\x00\x00\x02"
        writer.write(mbap + pdu)
        await writer.drain()

        # Read MBAP response header (7 bytes)
        resp_mbap = await reader.readexactly(7)
        tx, proto, length, unit = struct.unpack(">HHHB", resp_mbap)
        assert tx == 1
        assert proto == 0
        assert unit == 1

        # Read PDU response (length - 1 bytes)
        resp_pdu = await reader.readexactly(length - 1)
        # Expected: function_code=3, byte_count=4, data=[0x1234, 0x5678]
        assert resp_pdu == b"\x03\x04\x12\x34\x56\x78"

    finally:
        writer.close()
        await writer.wait_closed()


async def test_tcp_server_invalid_protocol_id(tcp_server: AsyncTcpServer) -> None:
    """Test that connection is closed immediately if protocol ID is not 0 (DoS fix)."""
    port = get_server_port(tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # Protocol ID = 1 (invalid)
        mbap = struct.pack(">HHHB", 1, 1, 6, 1)
        pdu = b"\x03\x00\x00\x00\x02"
        frame = mbap + pdu
        with patch("tmodbus.server.async_tcp.log_raw_traffic") as mock_log:
            writer.write(frame)
            await writer.drain()

            # Server should disconnect immediately without writing any response
            data = await reader.read(100)
            mock_log.assert_any_call("recv", mbap, is_error=True)
            assert len(data) == 0  # EOF received

    finally:
        writer.close()
        await writer.wait_closed()


async def test_tcp_server_invalid_pdu_length(tcp_server: AsyncTcpServer) -> None:
    """Test that connection is closed immediately if PDU length is invalid (DoS fix)."""
    port = get_server_port(tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # PDU length = 255 (so length = 256, which exceeds max allowed PDU length of 253 bytes)
        mbap = struct.pack(">HHHB", 1, 0, 256, 1)
        pdu = b"\x03" + b"\x00" * 254
        frame = mbap + pdu
        with patch("tmodbus.server.async_tcp.log_raw_traffic") as mock_log:
            writer.write(frame)
            await writer.drain()

            # Server should disconnect immediately
            data = await reader.read(100)
            mock_log.assert_any_call("recv", mbap, is_error=True)
            assert len(data) == 0  # EOF received

    finally:
        writer.close()
        await writer.wait_closed()


async def test_tcp_server_zero_pdu_length(tcp_server: AsyncTcpServer) -> None:
    """Test that connection is closed immediately if PDU length is 0 (DoS fix)."""
    port = get_server_port(tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # PDU length = 0 (so length = 1)
        mbap = struct.pack(">HHHB", 1, 0, 1, 1)
        with patch("tmodbus.server.async_tcp.log_raw_traffic") as mock_log:
            writer.write(mbap)
            await writer.drain()

            # Server should disconnect immediately
            data = await reader.read(100)
            mock_log.assert_any_call("recv", mbap, is_error=True)
            assert len(data) == 0  # EOF received

    finally:
        writer.close()
        await writer.wait_closed()


async def test_tcp_server_unsupported_function_code(tcp_server: AsyncTcpServer) -> None:
    """Test that unsupported function code returns ILLEGAL_FUNCTION exception and connection stays open."""
    port = get_server_port(tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # Function code 0x99 is unsupported
        mbap = struct.pack(">HHHB", 2, 0, 2, 1)
        pdu = b"\x99"
        frame = mbap + pdu
        with patch("tmodbus.server.async_tcp.log_raw_traffic") as mock_log:
            writer.write(frame)
            await writer.drain()

            # Should receive response: IllegalFunction (0x01)
            resp_mbap = await reader.readexactly(7)
            tx, _proto, length, _unit = struct.unpack(">HHHB", resp_mbap)
            assert tx == 2
            assert length == 3  # fc | 0x80 + error_code

            resp_pdu = await reader.readexactly(2)
            assert resp_pdu == b"\x99\x01"  # 0x99 | 0x80 = 0x99, error code = 1
            mock_log.assert_any_call("recv", frame, is_error=True)

    finally:
        writer.close()
        await writer.wait_closed()


async def test_tcp_server_abrupt_disconnect(tcp_server: AsyncTcpServer) -> None:
    """Test that server handles client disconnecting abruptly during header read cleanly."""
    port = get_server_port(tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # Send only 3 bytes of MBAP and disconnect
        with patch("tmodbus.server.async_tcp.log_raw_traffic") as mock_log:
            writer.write(b"\x00\x01\x00")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.05)
            mock_log.assert_any_call("recv", b"\x00\x01\x00", is_error=True)
    finally:
        pass

    # The server should handle this exception without crashing and remain running
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        mbap = struct.pack(">HHHB", 3, 0, 6, 1)
        pdu = b"\x03\x00\x00\x00\x02"
        writer.write(mbap + pdu)
        await writer.drain()
        resp_mbap = await reader.readexactly(7)
        assert len(resp_mbap) == 7
    finally:
        writer.close()
        await writer.wait_closed()


async def test_tcp_server_double_stop(tcp_server: AsyncTcpServer) -> None:
    """Test that stop() can be called multiple times safely."""
    await tcp_server.stop()
    # Call stop() again when self._server is None
    await tcp_server.stop()


async def test_tcp_server_serve_forever() -> None:
    """Test serve_forever() starts the server and blocks until cancelled."""
    router = ModbusRequestRouter()
    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)

    task = asyncio.create_task(server.serve_forever())
    await asyncio.sleep(0.05)
    assert server._server is not None
    assert server._server.is_serving()

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await server.stop()


async def test_tcp_server_subfunction_pdu_errors(tcp_server: AsyncTcpServer) -> None:
    """Test subfunction PDU missing sub-function code raises error."""
    port = get_server_port(tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    try:
        # Function code 43 (0x2B) is sub-function PDU
        # Send PDU with only function code (length of PDU = 1)
        mbap = struct.pack(">HHHB", 4, 0, 2, 1)
        pdu = b"\x2b"
        writer.write(mbap + pdu)
        await writer.drain()

        # Should receive response: IllegalFunction (0x01)
        await reader.readexactly(7)
        resp_pdu = await reader.readexactly(2)
        assert resp_pdu == b"\xab\x01"  # 0x2b | 0x80 = 0xab

        # Send invalid sub-function code (e.g. 0)
        mbap = struct.pack(">HHHB", 5, 0, 3, 1)
        pdu = b"\x2b\x00"
        writer.write(mbap + pdu)
        await writer.drain()

        await reader.readexactly(7)
        resp_pdu = await reader.readexactly(2)
        assert resp_pdu == b"\xab\x01"
    finally:
        writer.close()
        await writer.wait_closed()


async def test_tcp_server_non_server_pdu_class(tcp_server: AsyncTcpServer) -> None:
    """Test that resolving a PDU class which is not a server PDU raises ValueError."""

    class DummyClientOnlyPDU(BaseClientPDU[None]):
        function_code = 0x03

    port = get_server_port(tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    with patch("tmodbus.server.base.get_pdu_class", return_value=DummyClientOnlyPDU):
        try:
            mbap = struct.pack(">HHHB", 6, 0, 6, 1)
            pdu = b"\x03\x00\x00\x00\x02"
            writer.write(mbap + pdu)
            await writer.drain()

            await reader.readexactly(7)
            resp_pdu = await reader.readexactly(2)
            assert resp_pdu == b"\x83\x01"  # IllegalFunction
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()


async def test_tcp_server_client_handler_exception(tcp_server: AsyncTcpServer) -> None:
    """Test that generic exceptions in single request handling are handled cleanly."""
    port = get_server_port(tcp_server)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)

    with patch("tmodbus.server.async_tcp.handle_modbus_request", side_effect=RuntimeError("Generic Error")):
        try:
            mbap = struct.pack(">HHHB", 7, 0, 6, 1)
            pdu = b"\x03\x00\x00\x00\x02"
            writer.write(mbap + pdu)
            await writer.drain()

            # The connection should close due to the exception
            data = await reader.read(100)
            assert len(data) == 0
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()


async def test_tcp_server_raw_traffic_logging(tcp_server: AsyncTcpServer) -> None:
    """Test that TCP server logs raw traffic with is_error=True on errors."""
    port = get_server_port(tcp_server)

    with patch("tmodbus.server.async_tcp.log_raw_traffic") as mock_log:
        # 1. Invalid protocol ID
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            mbap = struct.pack(">HHHB", 1, 1, 6, 1)  # protocol_id = 1
            writer.write(mbap)
            await writer.drain()
            await reader.read(10)
        finally:
            writer.close()
            await writer.wait_closed()

        mock_log.assert_any_call("recv", mbap, is_error=True)

        # 2. Invalid PDU length
        mock_log.reset_mock()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            mbap = struct.pack(">HHHB", 1, 0, 256, 1)  # length = 256
            writer.write(mbap)
            await writer.drain()
            await reader.read(10)
        finally:
            writer.close()
            await writer.wait_closed()

        mock_log.assert_any_call("recv", mbap, is_error=True)

        # 3. Incomplete MBAP header
        mock_log.reset_mock()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"\x00\x01\x00")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

        await asyncio.sleep(0.05)  # allow server task to process the disconnect
        mock_log.assert_any_call("recv", b"\x00\x01\x00", is_error=True)

        # 4. Decoding failure (Invalid PDU format for FC 3)
        mock_log.reset_mock()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            mbap = struct.pack(">HHHB", 1, 0, 2, 1)  # length=2 (unit_id=1, fc=3)
            pdu = b"\x03"  # too short for FC 3
            writer.write(mbap + pdu)
            await writer.drain()
            await reader.read(10)
        finally:
            writer.close()
            await writer.wait_closed()

        mock_log.assert_any_call("recv", mbap + pdu, is_error=True)


async def test_tcp_server_read_exception(tcp_server: AsyncTcpServer) -> None:
    """Test that TCP server handles generic exceptions during reading cleanly."""
    port = get_server_port(tcp_server)
    _reader, writer = await asyncio.open_connection("127.0.0.1", port)

    call_count = 0

    async def mock_readexactly(_self: asyncio.StreamReader, n: int) -> bytes:
        nonlocal call_count
        call_count += 1
        if n == 7:
            return b"\x00\x01\x00\x00\x00\x06\x01"
        msg = "Connection error"
        raise OSError(msg)

    with patch("asyncio.StreamReader.readexactly", mock_readexactly):
        try:
            writer.write(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x02")
            await writer.drain()
            await asyncio.sleep(0.05)
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()


async def test_tcp_server_unregistered_unit_id() -> None:
    """Test that unregistered unit ID returns configured exception code."""
    router = ModbusRequestRouter()

    # Register only for unit_id=1
    @router.register(ReadHoldingRegistersPDU, unit_id=1)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x1234]

    # By default, unregistered_unit_id_exception_code = GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND (0x0B)
    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()

    try:
        port = get_server_port(server)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        try:
            # Request to unregistered unit_id=2
            mbap = struct.pack(">HHHB", 1, 0, 6, 2)
            pdu = b"\x03\x00\x00\x00\x01"  # ReadHoldingRegisters
            writer.write(mbap + pdu)
            await writer.drain()

            resp_mbap = await reader.readexactly(7)
            _tx, _proto, length, unit = struct.unpack(">HHHB", resp_mbap)
            assert unit == 2

            resp_pdu = await reader.readexactly(length - 1)
            # Exception response: function code = 0x83, exception code = 0x0B
            assert resp_pdu == b"\x83\x0b"

        finally:
            writer.close()
            await writer.wait_closed()

    finally:
        await server.stop()


async def test_tcp_server_configurable_exception_code() -> None:
    """Test that unregistered unit ID exception code is configurable (e.g. 0x0A)."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU, unit_id=1)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x1234]

    server = AsyncTcpServer(
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
            # Request to unregistered unit_id=2
            mbap = struct.pack(">HHHB", 1, 0, 6, 2)
            pdu = b"\x03\x00\x00\x00\x01"
            writer.write(mbap + pdu)
            await writer.drain()

            resp_mbap = await reader.readexactly(7)
            _tx, _proto, length, _unit = struct.unpack(">HHHB", resp_mbap)

            resp_pdu = await reader.readexactly(length - 1)
            # Exception response: function code = 0x83, exception code = 0x0A
            assert resp_pdu == b"\x83\x0a"

        finally:
            writer.close()
            await writer.wait_closed()

    finally:
        await server.stop()
