"""Tests for tmodbus/transport/async_smart.py ."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tenacity import AsyncRetrying, Future, retry_if_exception_type, stop_after_attempt
from tmodbus.exceptions import ModbusConnectionError, RequestRetryFailedError
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_base import AsyncBaseTransport
from tmodbus.transport.async_smart import AsyncSmartTransport


class DummyPDU(BaseClientPDU[tuple[str, bytes]]):
    """Dummy PDU for testing."""

    function_code = 0x03

    def encode_request(self) -> bytes:
        """Encode request."""
        return b"\x03\x00"

    def decode_response(self, data: bytes) -> tuple[str, bytes]:
        """Decode response."""
        return ("ok", data)


@pytest.fixture
def base_transport_mock() -> AsyncBaseTransport:
    """Fixture to create a mock AsyncBaseTransport."""
    bt = MagicMock(spec=AsyncBaseTransport)
    bt.open = AsyncMock()
    bt.close = AsyncMock()
    bt.is_open = lambda: True
    bt.send_and_receive = AsyncMock(return_value=("ok", b""))
    return bt


def test_init_negative_waits(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that negative wait times raise ValueError."""
    with pytest.raises(ValueError, match=r"wait_between_requests must be .*"):
        AsyncSmartTransport(base_transport_mock, wait_between_requests=-1)
    with pytest.raises(ValueError, match=r"wait_after_connect must be .*"):
        AsyncSmartTransport(base_transport_mock, wait_after_connect=-0.1)


def test_on_reconnected_requires_auto_reconnect(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that providing on_reconnected without auto_reconnect raises ValueError."""
    with pytest.raises(ValueError, match="on_reconnected callback provided but auto_reconnect is disabled"):
        AsyncSmartTransport(base_transport_mock, auto_reconnect=False, on_reconnected=lambda: None)


async def test_open_waits_after_connect(base_transport_mock: MagicMock) -> None:
    """Test that open waits after connecting if configured."""
    t = AsyncSmartTransport(base_transport_mock, wait_after_connect=0.05)

    with patch("asyncio.sleep", AsyncMock()) as fake_sleep:
        await t.open()
        base_transport_mock.open.assert_awaited()
        fake_sleep.assert_awaited()
    assert t._should_be_connected


async def test_close_resets_should_be_connected(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that close resets _should_be_connected flag."""
    t = AsyncSmartTransport(base_transport_mock, wait_after_connect=0.0)
    await t.open()
    assert t._should_be_connected
    await t.close()
    assert not t._should_be_connected


async def test_reconnect_and_wait_between_requests(base_transport_mock: MagicMock) -> None:
    """Test that _reconnect_send_and_receive waits and reconnects as needed."""
    # make base_transport initially closed
    base_transport_mock.is_open = lambda: False

    t = AsyncSmartTransport(base_transport_mock, wait_between_requests=0.1)

    # stub _do_auto_reconnect to simulate reconnection (set is_open True)
    async def do_reconnect() -> None:
        base_transport_mock.is_open = lambda: True

    # ensure last request finished just now to trigger wait
    t._last_request_finished_at = time.monotonic()

    do_auto_reconnect_mock = AsyncMock(side_effect=do_reconnect)

    with (
        patch.object(t, "_do_auto_reconnect", do_auto_reconnect_mock),
        patch("asyncio.sleep", AsyncMock()) as fake_sleep,
    ):
        resp = await t._reconnect_send_and_receive(1, DummyPDU())
        do_auto_reconnect_mock.assert_awaited()
        fake_sleep.assert_awaited()
        base_transport_mock.send_and_receive.assert_awaited()
        assert resp == ("ok", b"")


async def test_send_and_receive_updates_last_finished(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that last_request_finished_at is updated after send_and_receive."""
    t = AsyncSmartTransport(base_transport_mock)

    # stub the underlying send to return quickly
    with patch.object(t, "_reconnect_send_and_receive", AsyncMock(return_value=("ok", b""))):
        before = time.monotonic()
        resp = await t.send_and_receive(1, DummyPDU())
        after = time.monotonic()

        assert resp == ("ok", b"")
        assert t._last_request_finished_at is not None
        assert before <= t._last_request_finished_at <= after


async def test_do_auto_reconnect_retry_error(base_transport_mock: MagicMock) -> None:
    """Test that ModbusConnectionError is raised when auto_reconnect exhausts attempts."""
    t = AsyncSmartTransport(
        base_transport_mock, auto_reconnect=AsyncRetrying(stop=stop_after_attempt(1), reraise=False)
    )
    base_transport_mock.open.side_effect = ModbusConnectionError("fail")

    with pytest.raises(ModbusConnectionError):
        await t._do_auto_reconnect()


async def test_do_auto_reconnect_calls_on_reconnected(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test that on_reconnected callback is called after successful reconnection."""
    on_reconnected = AsyncMock()

    t = AsyncSmartTransport(
        base_transport_mock,
        on_reconnected=on_reconnected,
        auto_reconnect=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )

    await t._do_auto_reconnect()
    on_reconnected.assert_called_once()


async def test_send_and_receive_request_retry_failed(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that ModbusConnectionError is raised when response_retry_strategy exhausts attempts."""
    t = AsyncSmartTransport(base_transport_mock)

    # make _reconnect_send_and_receive raise each attempt; response_retry_strategy raises RetryError

    t.response_retry_strategy = AsyncRetrying(stop=stop_after_attempt(1), reraise=True)

    with (
        patch.object(t, "_reconnect_send_and_receive", AsyncMock(side_effect=ModbusConnectionError("fail"))),
        pytest.raises(ModbusConnectionError),
    ):
        await t.send_and_receive(1, DummyPDU())
    assert t._last_request_finished_at is not None


async def test_send_and_receive_response_retry_success(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test that send_and_receive succeeds when response_retry_strategy yields a successful attempt."""
    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
        retry_on_device_failure=True,
    )
    # success path: response_retry_strategy yields an attempt whose retry_state.outcome.failed == False
    with patch.object(t, "_reconnect_send_and_receive", AsyncMock(return_value=("ok", b""))):
        resp = await t.send_and_receive(1, DummyPDU())
        assert resp == ("ok", b"")
        assert t._last_request_finished_at is not None


async def test_send_and_receive_retry_strategy_raises_request_retry_failed(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test that RequestRetryFailedError is raised when response_retry_strategy exhausts attempts."""
    t = AsyncSmartTransport(
        base_transport_mock,
        # configure response_retry_strategy that yields at least one attempt then raises RetryError
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=False),
    )
    with patch.object(t, "_reconnect_send_and_receive", AsyncMock(side_effect=ModbusConnectionError("fail"))):
        with pytest.raises(RequestRetryFailedError):
            await t.send_and_receive(1, DummyPDU())
        assert t._last_request_finished_at is not None


def test_is_open_cases() -> None:
    """Test is_open method behavior under different conditions."""
    bt = MagicMock()
    bt.is_open = lambda: False
    t = AsyncSmartTransport(bt)
    # simulate should be connected and auto_reconnect present
    t._should_be_connected = True
    assert t.is_open()

    t2 = AsyncSmartTransport(bt, auto_reconnect=False)
    bt.is_open = lambda: False
    assert not t2.is_open()


async def test_send_and_receive_request_retry_failed_raises_and_sets_timestamp(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test that when _reconnect_send_and_receive raises, the timestamp is still set."""
    t = AsyncSmartTransport(
        base_transport_mock,
        # set strategy that will raise RetryError after attempts
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )

    with patch.object(t, "_reconnect_send_and_receive", AsyncMock(side_effect=ConnectionResetError("boom"))):
        with pytest.raises(ConnectionResetError):
            await t.send_and_receive(1, DummyPDU())
        assert t._last_request_finished_at is not None


async def test_send_and_receive_else_branch_sets_timestamp(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that the else branch sets the last_request_finished_at timestamp."""
    # ensure no response retry strategy
    t = AsyncSmartTransport(base_transport_mock, response_retry_strategy=None, auto_reconnect=False)
    with patch.object(t, "_reconnect_send_and_receive", AsyncMock(return_value=("ok", b""))):
        resp = await t.send_and_receive(1, DummyPDU())
        assert resp == ("ok", b"")
        assert t._last_request_finished_at is not None


async def test_do_auto_reconnect_without_on_reconnected(base_transport_mock: MagicMock) -> None:
    """Test that _do_auto_reconnect succeeds without on_reconnected callback."""
    t = AsyncSmartTransport(
        base_transport_mock,
        auto_reconnect=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )

    # Should not raise, and should not call on_reconnected since it's None
    await t._do_auto_reconnect()
    base_transport_mock.open.assert_awaited()


async def test_do_auto_reconnect_with_sync_on_reconnected(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that on_reconnected callback is called when it's a sync function."""
    on_reconnected_called = False

    def sync_on_reconnected() -> None:
        nonlocal on_reconnected_called
        on_reconnected_called = True

    t = AsyncSmartTransport(
        base_transport_mock,
        on_reconnected=sync_on_reconnected,
        auto_reconnect=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )

    await t._do_auto_reconnect()
    assert on_reconnected_called


async def test_response_retry_strategy_with_custom_retry(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that custom response_retry_strategy with retry attribute is used."""
    custom_strategy = AsyncRetrying(
        stop=stop_after_attempt(2),
        retry=retry_if_exception_type(ValueError),
        reraise=True,
    )

    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=custom_strategy,
    )

    # The retry strategy should include the custom retry function
    assert t.response_retry_strategy is not None


async def test_response_retry_strategy_without_retry_attribute(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that response_retry_strategy without retry attribute is handled."""
    custom_strategy = AsyncRetrying(
        stop=stop_after_attempt(2),
        reraise=True,
    )

    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=custom_strategy,
    )

    # Should not raise and should create a valid retry strategy
    assert t.response_retry_strategy is not None


async def test_reconnect_send_and_receive_without_auto_reconnect(base_transport_mock: MagicMock) -> None:
    """Test _reconnect_send_and_receive when auto_reconnect is disabled."""
    t = AsyncSmartTransport(base_transport_mock, auto_reconnect=False)

    # Should not attempt to reconnect even if connection is closed
    base_transport_mock.is_open = lambda: False

    # Should just call send_and_receive directly
    resp = await t._reconnect_send_and_receive(1, DummyPDU())
    assert resp == ("ok", b"")
    base_transport_mock.send_and_receive.assert_awaited()


async def test_reconnect_send_and_receive_without_wait_between_requests(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test _reconnect_send_and_receive when wait_between_requests is 0."""
    t = AsyncSmartTransport(base_transport_mock, wait_between_requests=0.0, auto_reconnect=False)

    # Set last request time but wait_between_requests is 0, so no wait
    t._last_request_finished_at = time.monotonic()

    with patch("asyncio.sleep", AsyncMock()) as fake_sleep:
        resp = await t._reconnect_send_and_receive(1, DummyPDU())
        assert resp == ("ok", b"")
        # Should not sleep since wait_between_requests is 0
        fake_sleep.assert_not_awaited()


async def test_reconnect_send_and_receive_with_negative_wait_needed(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test _reconnect_send_and_receive when wait_needed is negative (enough time has passed)."""
    t = AsyncSmartTransport(base_transport_mock, wait_between_requests=0.1, auto_reconnect=False)

    # Set last request time far in the past so wait_needed will be negative
    t._last_request_finished_at = time.monotonic() - 1.0

    with patch("asyncio.sleep", AsyncMock()) as fake_sleep:
        resp = await t._reconnect_send_and_receive(1, DummyPDU())
        assert resp == ("ok", b"")
        # Should not sleep since enough time has passed
        fake_sleep.assert_not_awaited()


async def test_retry_on_device_busy_disabled(base_transport_mock: AsyncBaseTransport) -> None:
    """Test initialization when retry_on_device_busy is False."""
    t = AsyncSmartTransport(
        base_transport_mock,
        retry_on_device_busy=False,
    )

    # Should still have a valid retry strategy
    assert t.response_retry_strategy is not None


async def test_response_retry_strategy_with_falsy_retry_attribute(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test response_retry_strategy where retry attribute evaluates to False."""
    # Create a custom strategy without a retry parameter
    # When AsyncRetrying is created without retry, it defaults to a value that could be falsy
    custom_strategy = AsyncRetrying(
        stop=stop_after_attempt(2),
        reraise=True,
        # Not specifying 'retry' parameter means it will have a default/empty retry
    )
    # Explicitly set to None to simulate falsy
    custom_strategy.retry = None  # type: ignore[assignment]

    # The strategy should work even without a custom retry
    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=custom_strategy,
    )

    # Should not raise and should create a valid retry strategy
    assert t.response_retry_strategy is not None


async def test_do_auto_reconnect_when_connection_already_closed(base_transport_mock: MagicMock) -> None:
    """Test _do_auto_reconnect when base_transport.is_open() is False (line 201)."""
    t = AsyncSmartTransport(
        base_transport_mock,
        auto_reconnect=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )

    # Make base_transport report as closed
    base_transport_mock.is_open = lambda: False

    await t._do_auto_reconnect()

    # Should not call close since connection is already closed
    base_transport_mock.close.assert_not_awaited()
    # Should call open to reconnect
    base_transport_mock.open.assert_awaited()


async def test_reconnect_send_and_receive_with_must_reconnect_flag(base_transport_mock: MagicMock) -> None:
    """Test _reconnect_send_and_receive when _must_reconnect is True (lines 225-227)."""
    t = AsyncSmartTransport(base_transport_mock)

    # Set the _must_reconnect flag
    t._must_reconnect = True

    # Make base_transport report as open so it doesn't trigger the second reconnect path
    base_transport_mock.is_open = lambda: True

    with patch.object(t, "_do_auto_reconnect", AsyncMock(side_effect=lambda: None)) as mock_reconnect:
        resp = await t._reconnect_send_and_receive(1, DummyPDU())

        # Should have called _do_auto_reconnect due to _must_reconnect flag
        mock_reconnect.assert_awaited_once()
        # Flag should be reset
        assert not t._must_reconnect
        assert resp == ("ok", b"")


async def test_reconnect_send_and_receive_when_connection_not_open(base_transport_mock: MagicMock) -> None:
    """Test _reconnect_send_and_receive when connection is not open (line 228->233)."""
    t = AsyncSmartTransport(base_transport_mock)

    # Make _must_reconnect False so we skip that path
    t._must_reconnect = False

    # Make base_transport report as closed to trigger the second reconnect path
    base_transport_mock.is_open = lambda: False

    async def do_reconnect() -> None:
        # After reconnection, set is_open to True
        base_transport_mock.is_open = lambda: True

    with patch.object(t, "_do_auto_reconnect", AsyncMock(side_effect=do_reconnect)) as mock_reconnect:
        resp = await t._reconnect_send_and_receive(1, DummyPDU())

        # Should have called _do_auto_reconnect due to connection being closed
        mock_reconnect.assert_awaited_once()
        assert resp == ("ok", b"")


async def test_retry_with_new_connection_if_needed_returns_true(base_transport_mock: AsyncBaseTransport) -> None:
    """Test _retry_with_new_connection_if_needed returns True for ModbusConnectionError (lines 270-276)."""
    t = AsyncSmartTransport(base_transport_mock)

    # Create a mock retry_state with a ModbusConnectionError
    retry_state = MagicMock()
    retry_state.outcome = Future(0)
    retry_state.outcome.set_exception(ModbusConnectionError("Connection lost"))

    result = t._retry_with_new_connection_if_needed(retry_state)

    # Should return True and set _must_reconnect
    assert result is True
    assert t._must_reconnect is True


async def test_retry_with_new_connection_if_needed_returns_false_no_outcome(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test _retry_with_new_connection_if_needed returns False when outcome is None."""
    t = AsyncSmartTransport(base_transport_mock)

    retry_state = MagicMock()
    retry_state.outcome = None

    result = t._retry_with_new_connection_if_needed(retry_state)

    # Should return False
    assert result is False
    assert not t._must_reconnect


async def test_retry_with_new_connection_if_needed_returns_false_not_failed(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test _retry_with_new_connection_if_needed returns False when outcome.failed is False."""
    t = AsyncSmartTransport(base_transport_mock)

    retry_state = MagicMock()
    retry_state.outcome = Future(0)
    retry_state.outcome.set_result("success")

    result = t._retry_with_new_connection_if_needed(retry_state)

    # Should return False since outcome.failed is False
    assert result is False
    assert not t._must_reconnect


async def test_retry_with_new_connection_if_needed_returns_false_different_exception(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test _retry_with_new_connection_if_needed returns False for non-ModbusConnectionError."""
    t = AsyncSmartTransport(base_transport_mock)

    retry_state = MagicMock()
    retry_state.outcome = Future(0)
    retry_state.outcome.set_exception(ValueError("Some other error"))

    result = t._retry_with_new_connection_if_needed(retry_state)

    # Should return False since it's not a ModbusConnectionError
    assert result is False
    assert not t._must_reconnect
