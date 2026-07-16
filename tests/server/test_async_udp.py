"""Tests for tmodbus/server/async_udp.py."""

import asyncio
import struct
from collections.abc import AsyncIterator
from unittest.mock import MagicMock, patch

import pytest
from tmodbus.pdu import ReadHoldingRegistersPDU
from tmodbus.server import AsyncUdpServer, ModbusRequestRouter
from tmodbus.server.async_udp import ModbusUdpServerProtocol


@pytest.fixture
async def udp_server() -> AsyncIterator[AsyncUdpServer]:
    """Fixture to start a Modbus UDP server on a free local port."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x1234, 0x5678]

    # Use port=0 so OS dynamically allocates a free port
    server = AsyncUdpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    yield server
    await server.stop()


def get_server_port(server: AsyncUdpServer) -> int:
    """Get the dynamic port allocated to the UDP server."""
    assert len(server.sockets) > 0
    addr = server.sockets[0].getsockname()
    assert isinstance(addr, tuple)
    return int(addr[1])


class UdpClientProtocol(asyncio.DatagramProtocol):
    """Simple DatagramProtocol for testing the Modbus UDP server."""

    transport: asyncio.DatagramTransport | None

    def __init__(self) -> None:
        """Initialize test UDP client protocol."""
        self.transport = None
        self.future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Handle connection made event."""
        if not isinstance(transport, asyncio.DatagramTransport):
            msg = "Expected DatagramTransport"
            raise TypeError(msg)
        self.transport = transport

    def datagram_received(self, data: bytes, _addr: tuple[str, int] | None) -> None:
        """Handle received datagram from server."""
        self.future.set_result(data)


async def test_udp_server_happy_path(udp_server: AsyncUdpServer) -> None:
    """Test successful request/response transaction on the UDP server."""
    port = get_server_port(udp_server)
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(UdpClientProtocol, remote_addr=("127.0.0.1", port))

    try:
        # Build Read Holding Registers request: transaction_id=1, protocol_id=0, length=6, unit_id=1
        # PDU: function_code=3, start_address=0, quantity=2
        mbap = struct.pack(">HHHB", 1, 0, 6, 1)
        pdu = b"\x03\x00\x00\x00\x02"
        transport.sendto(mbap + pdu)

        resp = await asyncio.wait_for(protocol.future, timeout=1.0)
        assert len(resp) >= 7

        tx, proto, _length, unit = struct.unpack(">HHHB", resp[:7])
        assert tx == 1
        assert proto == 0
        assert unit == 1

        resp_pdu = resp[7:]
        # Expected: function_code=3, byte_count=4, data=[0x1234, 0x5678]
        assert resp_pdu == b"\x03\x04\x12\x34\x56\x78"

    finally:
        transport.close()


async def test_udp_server_invalid_protocol_id(udp_server: AsyncUdpServer) -> None:
    """Test that request with invalid protocol ID is ignored (no response)."""
    port = get_server_port(udp_server)
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(UdpClientProtocol, remote_addr=("127.0.0.1", port))

    try:
        # Protocol ID = 1 (invalid)
        mbap = struct.pack(">HHHB", 1, 1, 6, 1)
        pdu = b"\x03\x00\x00\x00\x02"
        frame = mbap + pdu

        with patch("tmodbus.server.async_udp.log_raw_traffic") as mock_log:
            transport.sendto(frame)

            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(protocol.future, timeout=0.1)

            mock_log.assert_any_call("recv", frame, is_error=True)

    finally:
        transport.close()


async def test_udp_server_invalid_pdu_length(udp_server: AsyncUdpServer) -> None:
    """Test that request with too long PDU length is ignored (no response)."""
    port = get_server_port(udp_server)
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(UdpClientProtocol, remote_addr=("127.0.0.1", port))

    try:
        # PDU length = 255 (so length = 256, which exceeds max allowed length of 253 bytes)
        mbap = struct.pack(">HHHB", 1, 0, 256, 1)
        pdu = b"\x03" + b"\x00" * 254
        frame = mbap + pdu

        with patch("tmodbus.server.async_udp.log_raw_traffic") as mock_log:
            transport.sendto(frame)

            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(protocol.future, timeout=0.1)

            mock_log.assert_any_call("recv", frame, is_error=True)

    finally:
        transport.close()


async def test_udp_server_unsupported_function_code(udp_server: AsyncUdpServer) -> None:
    """Test that unsupported function code returns ILLEGAL_FUNCTION exception."""
    port = get_server_port(udp_server)
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(UdpClientProtocol, remote_addr=("127.0.0.1", port))

    try:
        # Function code 0x99 is unsupported
        mbap = struct.pack(">HHHB", 2, 0, 2, 1)
        pdu = b"\x99"
        frame = mbap + pdu

        transport.sendto(frame)

        resp = await asyncio.wait_for(protocol.future, timeout=1.0)
        assert len(resp) >= 7

        tx, proto, _length, unit = struct.unpack(">HHHB", resp[:7])
        assert tx == 2
        assert proto == 0
        assert unit == 1

        resp_pdu = resp[7:]
        # Illegal function code exception response: 0x99 | 0x80 = 0x19, exception = 0x01
        assert resp_pdu == b"\x99\x01"

    finally:
        transport.close()


async def test_udp_server_start_twice(udp_server: AsyncUdpServer) -> None:
    """Test starting the server twice returns early."""
    await udp_server.start()  # Already started by fixture


async def test_udp_server_stop_not_started() -> None:
    """Test stopping a server that has not been started."""
    server = AsyncUdpServer(host="127.0.0.1", port=0, handler=ModbusRequestRouter())
    await server.stop()
    assert server.sockets == []


async def test_udp_server_serve_forever() -> None:
    """Test serve_forever starts and can be stopped directly."""
    server = AsyncUdpServer(host="127.0.0.1", port=0, handler=ModbusRequestRouter())
    task = asyncio.create_task(server.serve_forever())
    await asyncio.sleep(0.05)
    assert len(server.sockets) > 0
    await server.stop()
    await task
    assert len(server.sockets) == 0


async def test_udp_server_serve_forever_cancelled() -> None:
    """Test serve_forever starts and handles CancelledError."""
    server = AsyncUdpServer(host="127.0.0.1", port=0, handler=ModbusRequestRouter())
    task = asyncio.create_task(server.serve_forever())
    await asyncio.sleep(0.05)
    assert len(server.sockets) > 0
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(server.sockets) == 0


async def test_server_protocol_connection_made_type_error() -> None:
    """Test connection_made raises TypeError when transport is not a DatagramTransport."""
    protocol = ModbusUdpServerProtocol(ModbusRequestRouter(), unregistered_unit_id_exception_code=0x0B)
    mock_transport = MagicMock(spec=asyncio.WriteTransport)  # TCP transport
    with pytest.raises(TypeError, match="Expected a DatagramTransport"):
        protocol.connection_made(mock_transport)


async def test_udp_server_packet_too_short(udp_server: AsyncUdpServer) -> None:
    """Test that a packet shorter than 7 bytes is logged as error and ignored."""
    port = get_server_port(udp_server)
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(UdpClientProtocol, remote_addr=("127.0.0.1", port))

    try:
        with patch("tmodbus.server.async_udp.log_raw_traffic") as mock_log:
            # Send a 5-byte packet
            transport.sendto(b"\x00\x01\x00\x00\x00")
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(protocol.future, timeout=0.1)
            mock_log.assert_any_call("recv", b"\x00\x01\x00\x00\x00", is_error=True)
    finally:
        transport.close()


async def test_udp_server_length_mismatch(udp_server: AsyncUdpServer) -> None:
    """Test datagram length mismatch is logged as error and ignored."""
    port = get_server_port(udp_server)
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(UdpClientProtocol, remote_addr=("127.0.0.1", port))

    try:
        # MBAP length field says length is 6, but we only send 5 bytes after MBAP
        mbap = struct.pack(">HHHB", 1, 0, 6, 1)
        pdu = b"\x03\x00\x00\x00"  # 4 bytes PDU, total 5 bytes after MBAP instead of 6
        frame = mbap + pdu

        with patch("tmodbus.server.async_udp.log_raw_traffic") as mock_log:
            transport.sendto(frame)
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(protocol.future, timeout=0.1)
            mock_log.assert_any_call("recv", frame, is_error=True)
    finally:
        transport.close()


async def test_udp_server_unregistered_unit_id() -> None:
    """Test that unregistered unit ID returns unregistered_unit_id_exception_code exception."""
    router = ModbusRequestRouter()

    # Register only for unit_id=1
    @router.register(ReadHoldingRegistersPDU, unit_id=1)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x1234]

    server = AsyncUdpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()

    port = get_server_port(server)
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(UdpClientProtocol, remote_addr=("127.0.0.1", port))

    try:
        # Unit ID = 99 is unregistered (only unit ID 1 is registered)
        mbap = struct.pack(">HHHB", 1, 0, 6, 99)
        pdu = b"\x03\x00\x00\x00\x01"
        frame = mbap + pdu

        transport.sendto(frame)
        resp = await asyncio.wait_for(protocol.future, timeout=1.0)
        assert len(resp) >= 7
        resp_pdu = resp[7:]
        assert resp_pdu == b"\x83\x0b"  # 0x03 | 0x80 = 0x83, exception code 0x0B
    finally:
        transport.close()
        await server.stop()


async def test_server_protocol_process_datagram_no_transport() -> None:
    """Test that _process_datagram doesn't crash when transport is None/closed."""
    protocol = ModbusUdpServerProtocol(ModbusRequestRouter(), unregistered_unit_id_exception_code=0x0B)
    protocol.transport = None  # No transport

    mbap = struct.pack(">HHHB", 1, 0, 6, 1)
    pdu = b"\x03\x00\x00\x00\x02"
    frame = mbap + pdu

    # Should not raise exception
    await protocol._process_datagram(frame, ("127.0.0.1", 1234))


async def test_server_protocol_process_datagram_exception() -> None:
    """Test that exceptions during _process_datagram are caught and logged."""
    protocol = ModbusUdpServerProtocol(ModbusRequestRouter(), unregistered_unit_id_exception_code=0x0B)

    mock_transport = MagicMock(spec=asyncio.DatagramTransport)
    protocol.connection_made(mock_transport)

    with (
        patch("struct.unpack", side_effect=RuntimeError("unexpected unpack error")),
        patch("tmodbus.server.async_udp.logger") as mock_logger,
    ):
        # Call it
        await protocol._process_datagram(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08", ("127.0.0.1", 1234))

        # Verify exception log was called
        mock_logger.exception.assert_called_with("Error processing UDP datagram from %s", ("127.0.0.1", 1234))
