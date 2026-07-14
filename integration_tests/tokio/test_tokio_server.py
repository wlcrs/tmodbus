"""Integration tests for tmodbus servers against a tokio-based Rust client."""

import asyncio
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).parent.parent))
from tmodbus.server import (
    AsyncRtuOverTcpServer,
    AsyncRtuServer,
    AsyncTcpServer,
)

from integration_test_server import ModbusDevice, setup_router

client_bin_path = Path(__file__).parent / "target/release/tokio-client"


def get_server_port(server: AsyncTcpServer | AsyncRtuOverTcpServer) -> int:
    """Get the dynamically allocated port from an active TCP server."""
    assert server._server is not None
    sockets = server._server.sockets
    assert sockets is not None
    assert len(sockets) > 0
    addr = sockets[0].getsockname()
    assert isinstance(addr, tuple)
    return int(addr[1])


@pytest.fixture
def virtual_serial_ports() -> Generator[tuple[Path, Path], None, None]:
    """Fixture to start socat to create a virtual serial port pair link."""
    server_socket_path = Path(__file__).parent / "tokio-server-socket-test"
    client_socket_path = Path(__file__).parent / "tokio-client-socket-test"

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
    """Test tmodbus TCP server against tokio-client."""
    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    try:
        # Run tokio-client against our TCP server
        process = await asyncio.create_subprocess_exec(
            str(client_bin_path),
            "tcp",
            f"127.0.0.1:{port}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, f"Client failed with output:\n{stdout.decode()}\n{stderr.decode()}"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rtu_over_tcp_server() -> None:
    """Test tmodbus RTU-over-TCP server against tokio-client."""
    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncRtuOverTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    try:
        # Run tokio-client against our RTU-over-TCP server
        process = await asyncio.create_subprocess_exec(
            str(client_bin_path),
            "rtu-over-tcp",
            f"127.0.0.1:{port}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, f"Client failed with output:\n{stdout.decode()}\n{stderr.decode()}"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_rtu_server(virtual_serial_ports: tuple[Path, Path]) -> None:
    """Test tmodbus RTU server against tokio-client."""
    server_port, client_port = virtual_serial_ports

    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncRtuServer(port=str(server_port), handler=router, baudrate=19200)
    await server.start()

    try:
        # Run tokio-client against our RTU server
        process = await asyncio.create_subprocess_exec(
            str(client_bin_path),
            "rtu",
            str(client_port),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, f"Client failed with output:\n{stdout.decode()}\n{stderr.decode()}"
    finally:
        await server.stop()
