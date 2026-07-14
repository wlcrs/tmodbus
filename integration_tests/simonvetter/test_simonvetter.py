"""Integration tests for tmodbus against the simonvetter/modbus client and server."""

import asyncio
import socket
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path

import pytest
from tmodbus.client import AsyncModbusClient

sys.path.append(str(Path(__file__).parent.parent))
from tmodbus.server import (
    AsyncRtuOverTcpServer,
    AsyncRtuServer,
    AsyncTcpServer,
)
from tmodbus.transport import AsyncTcpTransport

from integration_test_server import ModbusDevice, setup_router

client_bin_path = Path(__file__).parent / "client"
server_bin_path = Path(__file__).parent / "server"


def get_server_port(server: AsyncTcpServer | AsyncRtuOverTcpServer) -> int:
    """Get the dynamically allocated port from an active TCP server."""
    assert server._server is not None
    sockets = server._server.sockets
    assert sockets is not None
    assert len(sockets) > 0
    addr = sockets[0].getsockname()
    assert isinstance(addr, tuple)
    return int(addr[1])


def find_free_port() -> int:
    """Find a free port on localhost by binding a socket and releasing it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return int(port)


@pytest.fixture
def virtual_serial_ports() -> Generator[tuple[Path, Path], None, None]:
    """Fixture to start socat to create a virtual serial port pair link."""
    server_socket_path = Path(__file__).parent / "simonvetter-server-socket-test"
    client_socket_path = Path(__file__).parent / "simonvetter-client-socket-test"

    for path in (server_socket_path, client_socket_path):
        if path.exists():
            path.unlink()

    # Use socat to create a virtual serial port
    socat_process = subprocess.Popen(  # noqa: S603
        [
            "/usr/bin/socat",
            "-d",
            "-d",
            "-v",
            f"pty,rawer,echo=0,link={server_socket_path}",
            f"pty,rawer,echo=0,link={client_socket_path}",
        ],
    )

    # Wait for the ports to be created
    for _ in range(30):
        if server_socket_path.exists() and client_socket_path.exists():
            break
        time.sleep(0.1)
    else:
        socat_process.terminate()
        msg = "Failed to create virtual serial ports via socat"
        raise RuntimeError(msg)

    yield server_socket_path, client_socket_path

    socat_process.terminate()
    socat_process.wait()
    for path in (server_socket_path, client_socket_path):
        if path.exists():
            path.unlink()


@pytest.mark.asyncio
async def test_tcp_server() -> None:
    """Test tmodbus TCP server against Go client."""
    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    try:
        # Run Go client against our TCP server
        process = await asyncio.create_subprocess_exec(
            str(client_bin_path),
            f"tcp://127.0.0.1:{port}",
            "1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, f"Client failed with output:\n{stdout.decode()}\n{stderr.decode()}"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rtu_over_tcp_server() -> None:
    """Test tmodbus RTU-over-TCP server against Go client."""
    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncRtuOverTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    try:
        # Run Go client against our RTU-over-TCP server
        process = await asyncio.create_subprocess_exec(
            str(client_bin_path),
            f"rtuovertcp://127.0.0.1:{port}",
            "1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, f"Client failed with output:\n{stdout.decode()}\n{stderr.decode()}"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rtu_server(virtual_serial_ports: tuple[Path, Path]) -> None:
    """Test tmodbus RTU server against Go client."""
    server_port, client_port = virtual_serial_ports

    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncRtuServer(port=str(server_port), handler=router, baudrate=19200)
    await server.start()

    try:
        # Run Go client against our RTU server
        process = await asyncio.create_subprocess_exec(
            str(client_bin_path),
            f"rtu://{client_port}",
            "1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, f"Client failed with output:\n{stdout.decode()}\n{stderr.decode()}"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_tcp_client() -> None:
    """Test tmodbus TCP client against Go server."""
    port = find_free_port()

    # Start Go server
    server_process = await asyncio.create_subprocess_exec(
        str(server_bin_path),
        f"tcp://127.0.0.1:{port}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Wait for the Go server to bind
    await asyncio.sleep(0.5)

    try:
        client = AsyncModbusClient(transport=AsyncTcpTransport("127.0.0.1", port), unit_id=1)
        await client.connect()

        # 1. Coils
        await client.write_single_coil(0, value=True)
        res = await client.read_coils(0, 1)
        assert res == [True]

        await client.write_multiple_coils(5, [True, False, True, True])
        res = await client.read_coils(5, 4)
        assert res == [True, False, True, True]

        # 2. Discrete Inputs
        res = await client.read_discrete_inputs(0, 4)
        assert res == [True, False, True, False]

        # 3. Holding Registers
        await client.write_single_register(10, 42)
        res = await client.read_holding_registers(10, 1)
        assert res == [42]

        await client.write_multiple_registers(20, [100, 200, 300])
        res = await client.read_holding_registers(20, 3)
        assert res == [100, 200, 300]

        # 4. Input Registers
        res = await client.read_input_registers(0, 2)
        assert res == [1234, 5678]

        await client.disconnect()
    finally:
        server_process.terminate()
        await server_process.wait()
