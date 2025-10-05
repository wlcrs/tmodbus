import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tenacity import AsyncRetrying, stop_after_attempt

from tmodbus.exceptions import ModbusConnectionError, RequestRetryFailedError
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_smart import AsyncSmartTransport
from tmodbus.transport.base import BaseTransport


class DummyPDU(BaseClientPDU):
    function_code = 0x03

    def encode_request(self) -> bytes:
        """Encode request."""
        return b"\x03\x00"

    def decode_response(self, data: bytes):
        """Decode response."""
        return ("ok", data)


@pytest.fixture
def base_transport_mock() -> BaseTransport:
    bt = MagicMock(spec=BaseTransport)
    bt.open = AsyncMock()
    bt.close = AsyncMock()
    bt.is_open = lambda: True
    bt.send_and_receive = AsyncMock(return_value=("ok", b""))
    return bt


def test_init_negative_waits(base_transport_mock):
    with pytest.raises(ValueError, match=r"wait_between_requests must be .*"):
        AsyncSmartTransport(base_transport_mock, wait_between_requests=-1)
    with pytest.raises(ValueError, match=r"wait_after_connect must be .*"):
        AsyncSmartTransport(base_transport_mock, wait_after_connect=-0.1)


def test_on_reconnected_requires_auto_reconnect(base_transport_mock):
    with pytest.raises(ValueError, match="on_reconnected callback provided but auto_reconnect is disabled"):
        AsyncSmartTransport(base_transport_mock, auto_reconnect=False, on_reconnected=lambda: None)


async def test_open_waits_after_connect(base_transport_mock):
    t = AsyncSmartTransport(base_transport_mock, wait_after_connect=0.05)

    with patch("asyncio.sleep", AsyncMock()) as fake_sleep:
        await t.open()
        base_transport_mock.open.assert_awaited()
        fake_sleep.assert_awaited()
    assert t._should_be_connected


async def test_close_resets_should_be_connected(base_transport_mock):
    t = AsyncSmartTransport(base_transport_mock, wait_after_connect=0.0)
    await t.open()
    assert t._should_be_connected
    await t.close()
    assert not t._should_be_connected


async def test_reconnect_and_wait_between_requests(base_transport_mock):
    # make base_transport initially closed
    base_transport_mock.is_open = lambda: False

    t = AsyncSmartTransport(base_transport_mock, wait_between_requests=0.1)

    # stub _do_auto_reconnect to simulate reconnection (set is_open True)
    async def do_reconnect() -> None:
        base_transport_mock.is_open = lambda: True

    t._do_auto_reconnect = AsyncMock(side_effect=do_reconnect)

    # ensure last request finished just now to trigger wait
    t._last_request_finished_at = time.monotonic()

    with patch("asyncio.sleep", AsyncMock()) as fake_sleep:
        resp = await t._reconnect_send_and_receive(1, DummyPDU())
        t._do_auto_reconnect.assert_awaited()
        fake_sleep.assert_awaited()
        base_transport_mock.send_and_receive.assert_awaited()
        assert resp == ("ok", b"")


async def test_send_and_receive_updates_last_finished(base_transport_mock):
    t = AsyncSmartTransport(base_transport_mock)

    # stub the underlying send to return quickly
    t._reconnect_send_and_receive = AsyncMock(return_value=("ok", b""))

    before = time.monotonic()
    resp = await t.send_and_receive(1, DummyPDU())
    after = time.monotonic()

    assert resp == ("ok", b"")
    assert t._last_request_finished_at is not None
    assert before <= t._last_request_finished_at <= after


async def test_do_auto_reconnect_retry_error(monkeypatch, base_transport_mock):
    t = AsyncSmartTransport(
        base_transport_mock, auto_reconnect=AsyncRetrying(stop=stop_after_attempt(1), reraise=False)
    )
    base_transport_mock.open.side_effect = ModbusConnectionError("fail")

    with pytest.raises(ModbusConnectionError):
        await t._do_auto_reconnect()


async def test_do_auto_reconnect_calls_on_reconnected(monkeypatch, base_transport_mock):
    on_reconnected = AsyncMock()

    t = AsyncSmartTransport(
        base_transport_mock,
        on_reconnected=on_reconnected,
        auto_reconnect=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )

    await t._do_auto_reconnect()
    on_reconnected.assert_called_once()


async def test_send_and_receive_request_retry_failed(base_transport_mock):
    t = AsyncSmartTransport(base_transport_mock)

    # make _reconnect_send_and_receive raise each attempt; response_retry_strategy raises RetryError
    t._reconnect_send_and_receive = AsyncMock(side_effect=ModbusConnectionError("fail"))
    t.response_retry_strategy = AsyncRetrying(stop=stop_after_attempt(1), reraise=True)

    with pytest.raises(ModbusConnectionError):
        await t.send_and_receive(1, DummyPDU())
    assert t._last_request_finished_at is not None


async def test_send_and_receive_response_retry_success(monkeypatch, base_transport_mock):
    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
        retry_on_device_failure=True,
    )
    # success path: response_retry_strategy yields an attempt whose retry_state.outcome.failed == False
    t._reconnect_send_and_receive = AsyncMock(return_value=("ok", b""))

    resp = await t.send_and_receive(1, DummyPDU())
    assert resp == ("ok", b"")
    assert t._last_request_finished_at is not None


async def test_send_and_receive_retry_strategy_raises_request_retry_failed(base_transport_mock):
    t = AsyncSmartTransport(
        base_transport_mock,
        # configure response_retry_strategy that yields at least one attempt then raises RetryError
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=False),
    )
    t._reconnect_send_and_receive = AsyncMock(side_effect=ModbusConnectionError("fail"))

    with pytest.raises(RequestRetryFailedError):
        await t.send_and_receive(1, DummyPDU())
    assert t._last_request_finished_at is not None


def test_is_open_cases():
    bt = MagicMock()
    bt.is_open = lambda: False
    t = AsyncSmartTransport(bt)
    # simulate should be connected and auto_reconnect present
    t._should_be_connected = True
    assert t.is_open()

    t2 = AsyncSmartTransport(bt, auto_reconnect=False)
    bt.is_open = lambda: False
    assert not t2.is_open()


async def test_send_and_receive_request_retry_failed_raises_and_sets_timestamp(base_transport_mock):
    t = AsyncSmartTransport(
        base_transport_mock,
        # set strategy that will raise RetryError after attempts
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )

    t._reconnect_send_and_receive = AsyncMock(side_effect=ConnectionResetError("boom"))

    with pytest.raises(ConnectionResetError):
        await t.send_and_receive(1, DummyPDU())
    assert t._last_request_finished_at is not None


async def test_send_and_receive_else_branch_sets_timestamp(base_transport_mock):
    # ensure no response retry strategy
    t = AsyncSmartTransport(base_transport_mock, response_retry_strategy=None, auto_reconnect=False)
    t._reconnect_send_and_receive = AsyncMock(return_value=("ok", b""))

    resp = await t.send_and_receive(1, DummyPDU())
    assert resp == ("ok", b"")
    assert t._last_request_finished_at is not None
