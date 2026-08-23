"""Tests that tmodbus.server works without the optional serialx package."""

import importlib
import sys
from collections.abc import Iterator
from types import ModuleType
from unittest.mock import patch

import pytest


@pytest.fixture
def server_without_serialx() -> Iterator[ModuleType]:
    """Reimport tmodbus.server with serialx blocked."""
    with patch.dict(sys.modules):
        for name in list(sys.modules):
            if name == "serialx" or name.startswith(("serialx.", "tmodbus")):
                del sys.modules[name]
        sys.modules["serialx"] = None  # type: ignore[assignment]  # make `import serialx` fail
        yield importlib.import_module("tmodbus.server")


async def test_import_and_tcp_server_without_serialx(server_without_serialx: ModuleType) -> None:
    """Importing tmodbus.server and using AsyncTcpServer works without serialx."""
    server = server_without_serialx.AsyncTcpServer("localhost", server_without_serialx.ModbusRequestRouter(), port=0)
    await server.start()
    await server.stop()


@pytest.mark.parametrize("class_name", ["AsyncRtuServer", "AsyncAsciiServer"])
async def test_serial_server_start_without_serialx(server_without_serialx: ModuleType, class_name: str) -> None:
    """Starting a serial server without serialx raises a helpful ImportError."""
    server = getattr(server_without_serialx, class_name)("/dev/ttyUSB0", server_without_serialx.ModbusRequestRouter())
    with pytest.raises(ImportError, match=r"pip install tmodbus\[async-serial\]"):
        await server.start()
