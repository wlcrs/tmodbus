from typing import Any

import pytest

import tmodbus
from tmodbus import create_async_rtu_client, create_async_tcp_client
from tmodbus.transport.async_base import AsyncBaseTransport


class _DummyTransport:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs


class _DummyClient:
    def __init__(self, transport: AsyncBaseTransport) -> None:
        self.transport = transport


# Patch AsyncSmartTransport, AsyncTcpTransport, AsyncRtuTransport, AsyncModbusClient for isolation
@pytest.fixture(autouse=True)
def patch_module():
    tmodbus.AsyncSmartTransport = _DummyTransport
    tmodbus.AsyncTcpTransport = _DummyTransport
    tmodbus.AsyncRtuTransport = _DummyTransport
    tmodbus.AsyncModbusClient = _DummyClient


async def test_create_async_tcp_client():
    client = create_async_tcp_client(
        "127.0.0.1",
        port=1502,
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


async def test_create_async_rtu_client():
    client = create_async_rtu_client(
        "/dev/ttyUSB0",
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
