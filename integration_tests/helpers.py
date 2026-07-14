"""Shared helper functions for integration tests."""

import contextlib
import socket
import subprocess
import time
from collections.abc import Generator
from pathlib import Path

from tmodbus.server import AsyncRtuOverTcpServer, AsyncTcpServer


@contextlib.contextmanager
def make_virtual_serial_ports(server_path: Path, client_path: Path) -> Generator[tuple[Path, Path], None, None]:
    """Context manager to start socat and create a virtual serial port pair link."""
    for path in (server_path, client_path):
        if path.exists():
            path.unlink()

    # Use socat to create a virtual serial port
    socat_process = subprocess.Popen(  # noqa: S603
        [
            "/usr/bin/socat",
            "-d",
            "-d",
            "-v",
            f"pty,rawer,echo=0,link={server_path}",
            f"pty,rawer,echo=0,link={client_path}",
        ],
    )

    try:
        # Wait for the ports to be created
        for _ in range(30):
            if server_path.exists() and client_path.exists():
                break
            time.sleep(0.1)
        else:
            socat_process.terminate()
            msg = "Failed to create virtual serial ports via socat"
            raise RuntimeError(msg)

        yield server_path, client_path
    finally:
        socat_process.terminate()
        socat_process.wait()
        for path in (server_path, client_path):
            if path.exists():
                path.unlink()


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
