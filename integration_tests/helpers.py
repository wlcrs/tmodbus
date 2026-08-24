"""Shared helper functions for integration tests."""

import contextlib
import os
import pty
import select
import socket
import termios
import threading
import time
from collections.abc import Generator, Iterator
from pathlib import Path

from tmodbus.server import AsyncRtuOverTcpServer, AsyncTcpServer


def _configure_raw_pty(fd: int) -> None:
    """Configure slave file descriptor in complete raw mode with modem control ignored."""
    os.set_inheritable(fd, False)  # noqa: FBT003
    with contextlib.suppress(termios.error):
        mode = termios.tcgetattr(fd)
        mode[0] = 0  # iflag: raw
        mode[1] = 0  # oflag: raw
        mode[2] = termios.CS8 | termios.CREAD | termios.CLOCAL  # cflag
        mode[3] = 0  # lflag: raw, echo disabled
        mode[6][termios.VMIN] = 1
        mode[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSAFLUSH, mode)


class VirtualSerialPorts:
    """Represents a virtual serial port pair with optional quirks."""

    def __init__(self, server_path: Path, client_path: Path) -> None:
        """Initialize virtual serial port paths."""
        self.server_path = server_path
        self.client_path = client_path

    def __iter__(self) -> Iterator[Path]:
        """Iterate over server and client paths for tuple unpacking."""
        yield self.server_path
        yield self.client_path

    def disable_server_echo(self) -> None:
        """Quirk helper: explicitly disable ECHO on the server PTY without acquiring controlling terminal."""
        target = str(self.server_path.resolve() if self.server_path.is_symlink() else self.server_path)
        with contextlib.suppress(OSError, termios.error):
            fd = os.open(target, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            try:
                mode = termios.tcgetattr(fd)
                mode[3] &= ~(termios.ECHO | termios.ECHOE | termios.ECHOK | termios.ECHONL)
                termios.tcsetattr(fd, termios.TCSANOW, mode)
            finally:
                os.close(fd)


def _forward_pty_traffic(
    master_a: int,
    master_b: int,
    stop_event: threading.Event,
) -> None:
    """Forward data bidirectionally between two master PTY file descriptors."""
    while not stop_event.is_set():
        try:
            readable, _, _ = select.select([master_a, master_b], [], [], 0.05)
        except (ValueError, OSError):
            if not stop_event.is_set():
                time.sleep(0.01)
            continue
        for fd in readable:
            try:
                data = os.read(fd, 4096)
                if data:
                    dest = master_b if fd == master_a else master_a
                    with contextlib.suppress(OSError):
                        os.write(dest, data)
            except OSError:
                time.sleep(0.01)


def _cleanup_paths(*paths: Path) -> None:
    """Safely remove symlinks or files if they exist."""
    for path in paths:
        if path.is_symlink() or path.exists():
            path.unlink()


def _cleanup_fds(*fds: int) -> None:
    """Safely close open file descriptors."""
    for fd in fds:
        with contextlib.suppress(OSError):
            os.close(fd)


@contextlib.contextmanager
def make_virtual_serial_ports(
    server_path: Path,
    client_path: Path,
) -> Generator[VirtualSerialPorts, None, None]:
    """Context manager to create a virtual serial port pair link without socat."""
    _cleanup_paths(server_path, client_path)

    master_a, slave_a = pty.openpty()
    master_b, slave_b = pty.openpty()

    _configure_raw_pty(slave_a)
    _configure_raw_pty(slave_b)
    os.set_inheritable(master_a, False)  # noqa: FBT003
    os.set_inheritable(master_b, False)  # noqa: FBT003

    slave_a_path = Path(os.ttyname(slave_a))
    slave_b_path = Path(os.ttyname(slave_b))

    _cleanup_fds(slave_a, slave_b)

    server_path.symlink_to(slave_a_path)
    client_path.symlink_to(slave_b_path)

    stop_event = threading.Event()
    thread = threading.Thread(
        target=_forward_pty_traffic,
        args=(master_a, master_b, stop_event),
        daemon=True,
    )
    thread.start()

    ports = VirtualSerialPorts(server_path, client_path)

    try:
        yield ports
    finally:
        stop_event.set()
        thread.join(timeout=0.5)
        _cleanup_paths(server_path, client_path)
        _cleanup_fds(master_a, master_b)


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
