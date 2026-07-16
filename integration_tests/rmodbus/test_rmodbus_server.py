"""Integration tests for tmodbus servers against an rmodbus-based Rust client."""

import asyncio
import sys
from collections.abc import Generator
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).parent.parent))
from tmodbus.server import (
    AsyncAsciiServer,
    AsyncRtuOverTcpServer,
    AsyncRtuServer,
    AsyncTcpServer,
)

from helpers import get_server_port, make_virtual_serial_ports
from integration_test_server import ModbusDevice, setup_router

client_bin_path = Path(__file__).parent / "target/release/client"


@pytest.fixture
def virtual_serial_ports() -> Generator[tuple[Path, Path], None, None]:
    """Fixture to start socat to create a virtual serial port pair link."""
    server_socket_path = Path(__file__).parent / "rmodbus-server-socket-test"
    client_socket_path = Path(__file__).parent / "rmodbus-client-socket-test"
    with make_virtual_serial_ports(server_socket_path, client_socket_path) as ports:
        yield ports


@pytest.mark.asyncio
async def test_tcp_server() -> None:
    """Test tmodbus TCP server against rmodbus client."""
    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    try:
        # Run rmodbus client against our TCP server
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
    """Test tmodbus RTU-over-TCP server against rmodbus client."""
    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncRtuOverTcpServer(host="127.0.0.1", port=0, handler=router)
    await server.start()
    port = get_server_port(server)

    try:
        # Run rmodbus client against our RTU-over-TCP server
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
    """Test tmodbus RTU server against rmodbus client."""
    server_port, client_port = virtual_serial_ports

    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncRtuServer(port=str(server_port), handler=router, baudrate=19200)
    await server.start()

    try:
        # Run rmodbus client against our RTU server
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


@pytest.mark.asyncio
async def test_ascii_server(virtual_serial_ports: tuple[Path, Path]) -> None:
    """Test tmodbus ASCII server against rmodbus client."""
    server_port, client_port = virtual_serial_ports

    device = ModbusDevice()
    router = setup_router(device)

    server = AsyncAsciiServer(port=str(server_port), handler=router, baudrate=19200)
    await server.start()

    try:
        # Run rmodbus client against our ASCII server
        process = await asyncio.create_subprocess_exec(
            str(client_bin_path),
            "ascii",
            str(client_port),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0, f"Client failed with output:\n{stdout.decode()}\n{stderr.decode()}"
    finally:
        await server.stop()
