"""Tests for tmodbus/ __init__.py functions."""

from collections.abc import Generator
from typing import Any
from unittest import mock

import pytest
import tmodbus
from tmodbus import (
    create_async_ascii_client,
    create_async_rtu_client,
    create_async_rtu_over_tcp_client,
    create_async_tcp_client,
)
from tmodbus.transport.async_base import AsyncBaseTransport


class _DummyTransport:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs


class _DummyClient:
    def __init__(self, transport: AsyncBaseTransport, *, unit_id: int) -> None:
        self.transport = transport
        self.unit_id = unit_id


# Patch AsyncSmartTransport, AsyncTcpTransport, AsyncRtuTransport, AsyncModbusClient for isolation
@pytest.fixture(autouse=True)
def patch_module() -> Generator[None, None, None]:
    """Patch tmodbus module classes for isolation."""
    with (
        mock.patch.object(tmodbus, "AsyncSmartTransport", _DummyTransport),
        mock.patch.object(tmodbus, "AsyncTcpTransport", _DummyTransport),
        mock.patch.object(tmodbus, "AsyncRtuTransport", _DummyTransport),
        mock.patch.object(tmodbus, "AsyncAsciiTransport", _DummyTransport),
        mock.patch.object(tmodbus, "AsyncModbusClient", _DummyClient),
        mock.patch.object(tmodbus, "AsyncRtuOverTcpTransport", _DummyTransport),
    ):
        yield


async def test_create_async_tcp_client() -> None:
    """Test create_async_tcp_client function."""
    client = create_async_tcp_client(
        "127.0.0.1",
        port=1502,
        unit_id=1,
        timeout=5.0,
        connect_timeout=2.0,
        wait_between_requests=0.1,
        wait_after_connect=0.2,
        auto_reconnect=False,
        on_reconnected=None,
        response_retry_strategy=None,
        retry_on_device_busy=False,
        retry_on_device_failure=True,
        extra=123,
    )
    assert isinstance(client, _DummyClient)
    # Check transport chain
    assert isinstance(client.transport, _DummyTransport)
    assert isinstance(client.transport.args[0], _DummyTransport)
    assert client.transport.args[0].args[0] == "127.0.0.1"
    assert client.transport.args[0].args[1] == 1502
    assert client.transport.args[0].kwargs["timeout"] == 5.0
    assert client.transport.args[0].kwargs["connect_timeout"] == 2.0
    assert client.transport.args[0].kwargs["extra"] == 123


async def test_create_async_rtu_client() -> None:
    """Test create_async_rtu_client function."""
    client = create_async_rtu_client(
        "/dev/ttyUSB0",
        unit_id=1,
        wait_between_requests=0.1,
        wait_after_connect=0.2,
        auto_reconnect=True,
        on_reconnected=None,
        response_retry_strategy=None,
        retry_on_device_busy=True,
        retry_on_device_failure=False,
        baudrate=9600,
        bytesize=8,
    )
    assert isinstance(client, _DummyClient)
    # Check transport chain
    assert isinstance(client.transport, _DummyTransport)
    assert isinstance(client.transport.args[0], _DummyTransport)
    assert client.transport.args[0].args[0] == "/dev/ttyUSB0"
    assert client.transport.args[0].kwargs["baudrate"] == 9600
    assert client.transport.args[0].kwargs["bytesize"] == 8


async def test_create_async_ascii_client() -> None:
    """Test create_async_ascii_client function."""
    client = create_async_ascii_client(
        "/dev/ttyUSB0",
        unit_id=1,
        wait_between_requests=0.1,
        wait_after_connect=0.2,
        auto_reconnect=True,
        on_reconnected=None,
        response_retry_strategy=None,
        retry_on_device_busy=True,
        retry_on_device_failure=False,
        baudrate=9600,
        bytesize=8,
    )
    assert isinstance(client, _DummyClient)
    # Check transport chain
    assert isinstance(client.transport, _DummyTransport)
    assert isinstance(client.transport.args[0], _DummyTransport)
    assert client.transport.args[0].args[0] == "/dev/ttyUSB0"
    assert client.transport.args[0].kwargs["baudrate"] == 9600
    assert client.transport.args[0].kwargs["bytesize"] == 8


async def test_create_async_rtu_over_tcp_client() -> None:
    """Test create_async_rtu_over_tcp_client function."""
    client = create_async_rtu_over_tcp_client(
        "127.0.0.1",
        port=1502,
        unit_id=1,
        timeout=5.0,
        connect_timeout=2.0,
        wait_between_requests=0.1,
        wait_after_connect=0.2,
        auto_reconnect=True,
        on_reconnected=None,
        response_retry_strategy=None,
        retry_on_device_busy=True,
        retry_on_device_failure=False,
        extra=456,
    )
    assert isinstance(client, _DummyClient)
    # Check transport chain
    assert isinstance(client.transport, _DummyTransport)
    assert isinstance(client.transport.args[0], _DummyTransport)
    assert client.transport.args[0].args[0] == "127.0.0.1"
    assert client.transport.args[0].args[1] == 1502
    assert client.transport.args[0].kwargs["timeout"] == 5.0
    assert client.transport.args[0].kwargs["connect_timeout"] == 2.0
    assert client.transport.args[0].kwargs["extra"] == 456
