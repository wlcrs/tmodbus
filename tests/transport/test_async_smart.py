"""Tests for tmodbus/transport/async_smart.py ."""

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from tenacity import (
    AsyncRetrying,
    Future,
    RetryCallState,
    retry_if_exception_type,
    stop_after_attempt,
    stop_never,
    wait_fixed,
    wait_none,
)
from tmodbus.exceptions import (
    ModbusConnectionError,
    RequestRetryFailedError,
    ServerDeviceBusyError,
)
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport import async_smart as async_smart_module
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


def test_on_connection_lost_forwarded_to_base_transport(base_transport_mock: AsyncBaseTransport) -> None:
    """on_connection_lost is forwarded to the base transport, where the socket lives."""

    def callback(_exc: Exception | None) -> None:
        pass

    AsyncSmartTransport(base_transport_mock, on_connection_lost=callback)

    assert base_transport_mock.on_connection_lost is callback


def test_on_connection_lost_works_without_auto_reconnect(base_transport_mock: AsyncBaseTransport) -> None:
    """Unlike on_reconnected, on_connection_lost is allowed when auto_reconnect is disabled."""

    def callback(_exc: Exception | None) -> None:
        pass

    # Must not raise.
    AsyncSmartTransport(base_transport_mock, auto_reconnect=False, on_connection_lost=callback)

    assert base_transport_mock.on_connection_lost is callback


def test_on_connection_lost_not_provided_keeps_base_callback(base_transport_mock: AsyncBaseTransport) -> None:
    """When no callback is passed, a callback set directly on the base transport is preserved."""

    def existing(_exc: Exception | None) -> None:
        pass

    base_transport_mock.on_connection_lost = existing
    AsyncSmartTransport(base_transport_mock)

    assert base_transport_mock.on_connection_lost is existing


def test_init_creates_instance_communication_state(base_transport_mock: AsyncBaseTransport) -> None:
    """Test that each transport instance has its own communication state."""
    t1 = AsyncSmartTransport(base_transport_mock)
    t2 = AsyncSmartTransport(base_transport_mock)

    assert t1._communication_lock is not t2._communication_lock
    assert "_communication_lock" in t1.__dict__
    assert "_should_be_connected" in t1.__dict__
    assert "_must_reconnect" in t1.__dict__

    t1._should_be_connected = True
    t1._must_reconnect = True
    assert not t2._should_be_connected
    assert not t2._must_reconnect


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
        with pytest.raises(
            RequestRetryFailedError,
            match=(
                r"Failed to get a valid response after 1 attempts.+"
                r"Last error: ModbusConnectionError: fail"
            ),
        ):
            await t.send_and_receive(1, DummyPDU())
        assert t._last_request_finished_at is not None


async def test_retry_logging_helpers_include_retry_cause(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that retry logging includes the retry cause."""
    retry_state = RetryCallState(AsyncRetrying(stop=stop_after_attempt(1), reraise=True), None, (), {})
    retry_state.set_exception((ModbusConnectionError, ModbusConnectionError("fail"), None))

    empty_retry_state = RetryCallState(
        AsyncRetrying(stop=stop_after_attempt(1), reraise=True), fn=None, args=(), kwargs={}
    )
    unknown_retry_state = MagicMock(
        spec=RetryCallState, outcome=MagicMock(failed=True, exception=MagicMock(return_value=None))
    )

    with caplog.at_level("DEBUG", logger="tmodbus.transport.async_smart"):
        async_smart_module._log_response_retry(retry_state)
        async_smart_module._log_auto_reconnect_retry(retry_state)

    assert async_smart_module._format_retry_cause(retry_state) == "ModbusConnectionError: fail"
    assert async_smart_module._format_retry_cause(empty_retry_state) == "unknown"
    assert async_smart_module._format_retry_cause(unknown_retry_state) == "unknown"
    assert any(
        "Retrying request after attempt 1 due to ModbusConnectionError: fail" in record.message
        for record in caplog.records
    )
    assert any(
        "Retrying connection after attempt 1 due to ModbusConnectionError: fail" in record.message
        for record in caplog.records
    )


async def test_retry_logging_helpers_skip_debug_logging_when_disabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that retry logging helpers do nothing when debug logging is disabled."""
    retry_state = RetryCallState(AsyncRetrying(stop=stop_after_attempt(1), reraise=True), None, (), {})
    retry_state.set_exception((ModbusConnectionError, ModbusConnectionError("fail"), None))

    with caplog.at_level("INFO", logger="tmodbus.transport.async_smart"):
        async_smart_module._log_response_retry(retry_state)
        async_smart_module._log_auto_reconnect_retry(retry_state)

    assert caplog.records == []


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


async def test_retry_strategy_force_sane_defaults(
    base_transport_mock: AsyncBaseTransport,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that response_retry_strategy with stop_never and wait_none is overridden to sane defaults."""
    # Create a custom strategy with stop_never and wait_none
    custom_strategy = AsyncRetrying()

    with caplog.at_level("DEBUG", logger="tmodbus.transport.async_smart"):
        t = AsyncSmartTransport(
            base_transport_mock,
            response_retry_strategy=custom_strategy,
        )

    assert any("Reverting to tmodbus stop/wait default values instead" in record.message for record in caplog.records)

    # The resulting strategy should not have stop_never and wait_none
    assert t.response_retry_strategy.stop != stop_never
    assert not isinstance(t.response_retry_strategy.wait, wait_none)


async def test_retry_with_new_connection_if_needed_includes_timeout_and_connection_error(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test _retry_with_new_connection_if_needed returns True for TimeoutError and ConnectionError."""
    t = AsyncSmartTransport(base_transport_mock)

    for exc in (TimeoutError("request timed out"), ConnectionError("connection broken")):
        retry_state = MagicMock()
        retry_state.outcome = Future(0)
        retry_state.outcome.set_exception(exc)

        result = t._retry_with_new_connection_if_needed(retry_state)
        assert result is True, f"Expected True for {type(exc).__name__}"
        assert t._must_reconnect is True


async def test_timeout_at_transaction_boundary_marks_must_reconnect_and_closes_transport(
    base_transport_mock: MagicMock,
) -> None:
    """Test that a TimeoutError during send_and_receive marks _must_reconnect and closes base_transport."""
    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )
    base_transport_mock.send_and_receive.side_effect = TimeoutError("Response timed out")

    with pytest.raises(TimeoutError):
        await t.send_and_receive(1, DummyPDU())

    assert t._must_reconnect is True
    base_transport_mock.close.assert_awaited()
    assert t._reconnect_state is not None
    assert t._reconnect_state.attempt_number == 1
    assert t._next_reconnect_earliest == 0.0


async def test_persistent_backoff_progression_across_calls(
    base_transport_mock: MagicMock,
) -> None:
    """Test persistent backoff progression across separate calls to send_and_receive using default strategy."""
    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )

    # Underlying open succeeds immediately (like local modbus-proxy), but PDU times out
    base_transport_mock.is_open = lambda: True
    base_transport_mock.send_and_receive.side_effect = TimeoutError("stalled MCU")

    sleep_calls: list[float] = []

    async def fake_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    with patch("asyncio.sleep", side_effect=fake_sleep):
        # Call 1: Normal operation fails (initial error) -> wait=0s
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._must_reconnect is True
        assert t._reconnect_state is not None
        assert t._reconnect_state.attempt_number == 1
        assert t._next_reconnect_earliest == 0.0

        # Call 2: First recovery attempt -> executes immediately (wait=0s)
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._must_reconnect is True
        assert t._reconnect_state is not None
        assert t._reconnect_state.attempt_number == 2
        assert t._next_reconnect_earliest > 0.0

        # Call 3: Second recovery attempt -> backoff 1s
        # (DEFAULT_RECONNECT_RETRY_STRATEGY has wait_exponential min=0.1, max=10)
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._must_reconnect is True
        assert t._reconnect_state is not None
        assert t._reconnect_state.attempt_number == 3
        # Verify that sleep was called with ~1.0s
        assert any(0.8 <= call <= 1.1 for call in sleep_calls)

        # Call 4: Third recovery attempt -> backoff 2s
        sleep_calls.clear()
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._must_reconnect is True
        assert t._reconnect_state is not None
        assert t._reconnect_state.attempt_number == 4
        # Verify that sleep was called with ~2.0s
        assert any(1.8 <= call <= 2.1 for call in sleep_calls)


async def test_persistent_backoff_honors_user_wait_fixed(
    base_transport_mock: MagicMock,
) -> None:
    """Test that custom constant backoff strategy (wait_fixed) is honored during recovery."""
    t = AsyncSmartTransport(
        base_transport_mock,
        auto_reconnect=AsyncRetrying(wait=wait_fixed(5.0)),
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )

    base_transport_mock.is_open = lambda: True
    base_transport_mock.send_and_receive.side_effect = TimeoutError("stalled MCU")

    sleep_calls: list[float] = []

    async def fake_sleep(duration: float) -> None:
        sleep_calls.append(duration)

    with patch("asyncio.sleep", side_effect=fake_sleep):
        # Call 1: Initial failure -> wait=0s
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._next_reconnect_earliest == 0.0

        # Call 2: First recovery attempt executes immediately (wait=0s) and fails -> sets next backoff to 5.0s
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._next_reconnect_earliest > 0.0

        # Call 3: Second recovery attempt -> sleeps ~5.0s before reconnecting
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert any(4.9 <= call <= 5.1 for call in sleep_calls)

        # Call 4: Third recovery attempt -> sleeps another ~5.0s (constant, not exponential!)
        sleep_calls.clear()
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert any(4.9 <= call <= 5.1 for call in sleep_calls)


async def test_attempt_number_sequence_across_consecutive_failures(
    base_transport_mock: MagicMock,
) -> None:
    """Test that attempt_number sequence is strictly 1, 2, 3, 4 without off-by-one errors."""
    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )
    base_transport_mock.is_open = lambda: True
    base_transport_mock.send_and_receive.side_effect = TimeoutError("stalled")

    with patch("asyncio.sleep", AsyncMock()):
        # Call 1: Normal operation fails -> state created at attempt 1
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._reconnect_state is not None
        assert t._reconnect_state.attempt_number == 1

        # Call 2: Recovery attempt fails -> prepared for attempt 2
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._reconnect_state is not None
        assert t._reconnect_state.attempt_number == 2

        # Call 3: Recovery attempt fails -> prepared for attempt 3
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._reconnect_state is not None
        assert t._reconnect_state.attempt_number == 3

        # Call 4: Recovery attempt fails -> prepared for attempt 4
        with pytest.raises(TimeoutError):
            await t.send_and_receive(1, DummyPDU())
        assert t._reconnect_state is not None
        assert t._reconnect_state.attempt_number == 4


async def test_before_sleep_callback_invoked_sync_and_async(
    base_transport_mock: MagicMock,
) -> None:
    """Test that both sync and async before_sleep callbacks are safely invoked with upcoming sleep duration."""
    sync_called: list[float] = []
    async_called: list[float] = []

    def sync_before_sleep(rs: RetryCallState) -> None:
        if rs.upcoming_sleep is not None:
            sync_called.append(rs.upcoming_sleep)

    async def async_before_sleep(rs: RetryCallState) -> None:
        if rs.upcoming_sleep is not None:
            async_called.append(rs.upcoming_sleep)

    # 1. Test sync before_sleep
    t_sync = AsyncSmartTransport(
        base_transport_mock,
        auto_reconnect=AsyncRetrying(wait=wait_fixed(3.0), before_sleep=sync_before_sleep),
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )
    base_transport_mock.is_open = lambda: True
    base_transport_mock.send_and_receive.side_effect = TimeoutError("fail")

    with patch("asyncio.sleep", AsyncMock()):
        with pytest.raises(TimeoutError):
            await t_sync.send_and_receive(1, DummyPDU())  # Initial failure (wait=0s)
        with pytest.raises(TimeoutError):
            await t_sync.send_and_receive(1, DummyPDU())  # Recovery failure -> triggers before_sleep(3.0)

    assert sync_called == [3.0]

    # 2. Test async before_sleep
    t_async = AsyncSmartTransport(
        base_transport_mock,
        auto_reconnect=AsyncRetrying(wait=wait_fixed(4.0), before_sleep=async_before_sleep),
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )
    with patch("asyncio.sleep", AsyncMock()):
        with pytest.raises(TimeoutError):
            await t_async.send_and_receive(1, DummyPDU())  # Initial failure
        with pytest.raises(TimeoutError):
            await t_async.send_and_receive(1, DummyPDU())  # Recovery failure -> triggers async before_sleep(4.0)

    assert async_called == [4.0]


async def test_application_success_resets_recovery_state(
    base_transport_mock: MagicMock,
) -> None:
    """Test that a successful response resets recovery state and deadline."""
    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )
    assert isinstance(t.auto_reconnect, AsyncRetrying)
    # Simulate an established failure state
    t._reconnect_state = RetryCallState(t.auto_reconnect, fn=None, args=(), kwargs={})
    t._reconnect_state.attempt_number = 3
    t._next_reconnect_earliest = time.monotonic() + 100.0
    t._must_reconnect = True

    base_transport_mock.send_and_receive.return_value = ("ok", b"")

    with patch("asyncio.sleep", AsyncMock()):
        resp = await t.send_and_receive(1, DummyPDU())

    assert resp == ("ok", b"")
    assert t._reconnect_state is None
    assert t._next_reconnect_earliest == 0.0
    assert t._must_reconnect is False


async def test_modbus_response_error_resets_recovery_state(
    base_transport_mock: MagicMock,
) -> None:
    """Test that receiving a decoded Modbus exception (e.g. ServerDeviceBusyError) resets recovery state."""
    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
        retry_on_device_busy=False,
    )
    assert isinstance(t.auto_reconnect, AsyncRetrying)
    # Simulate an established failure state
    t._reconnect_state = RetryCallState(t.auto_reconnect, fn=None, args=(), kwargs={})
    t._reconnect_state.attempt_number = 2
    t._next_reconnect_earliest = time.monotonic() + 50.0
    t._must_reconnect = True

    base_transport_mock.send_and_receive.side_effect = ServerDeviceBusyError(0x03)

    with patch("asyncio.sleep", AsyncMock()), pytest.raises(ServerDeviceBusyError):
        await t.send_and_receive(1, DummyPDU())

    # Modbus exception response proves MCU is alive, so recovery state must be reset
    assert t._reconnect_state is None
    assert t._next_reconnect_earliest == 0.0
    assert t._must_reconnect is False


async def test_tcp_connect_failure_preserves_existing_auto_reconnect_behavior(
    base_transport_mock: MagicMock,
) -> None:
    """Test that TCP connect failure preserves inner Tenacity retries."""
    t = AsyncSmartTransport(
        base_transport_mock,
        auto_reconnect=AsyncRetrying(stop=stop_after_attempt(3), wait=wait_none()),
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )
    t._must_reconnect = True

    # _open fails twice with connection error, then succeeds on attempt 3
    open_attempts = 0

    async def counting_open() -> None:
        nonlocal open_attempts
        open_attempts += 1
        if open_attempts < 3:
            msg = "TCP connection refused"
            raise ModbusConnectionError(msg)

    base_transport_mock.open = AsyncMock(side_effect=counting_open)
    base_transport_mock.send_and_receive.return_value = ("ok", b"")

    resp = await t.send_and_receive(1, DummyPDU())
    assert resp == ("ok", b"")
    assert open_attempts == 3
    assert t._reconnect_state is None


async def test_on_reconnected_called_at_canonical_point(
    base_transport_mock: MagicMock,
) -> None:
    """Regression test: on_reconnected is awaited after _open() and before send_and_receive()."""
    call_order: list[str] = []

    async def mock_open() -> None:
        call_order.append("open")

    async def mock_on_reconnected() -> None:
        call_order.append("on_reconnected")

    async def mock_send_and_receive(_unit_id: int, _pdu: Any) -> tuple[str, bytes]:
        call_order.append("send_and_receive")
        return ("ok", b"")

    base_transport_mock.open = AsyncMock(side_effect=mock_open)
    base_transport_mock.send_and_receive = AsyncMock(side_effect=mock_send_and_receive)

    t = AsyncSmartTransport(
        base_transport_mock,
        auto_reconnect=AsyncRetrying(stop=stop_after_attempt(1)),
        on_reconnected=mock_on_reconnected,
    )
    t._must_reconnect = True

    await t.send_and_receive(1, DummyPDU())
    assert call_order == ["open", "on_reconnected", "send_and_receive"]


async def test_public_close_resets_recovery_state(
    base_transport_mock: AsyncBaseTransport,
) -> None:
    """Test that public close() resets recovery state and earliest deadline."""
    t = AsyncSmartTransport(base_transport_mock)
    assert isinstance(t.auto_reconnect, AsyncRetrying)
    t._reconnect_state = RetryCallState(t.auto_reconnect, fn=None, args=(), kwargs={})
    t._reconnect_state.attempt_number = 3
    t._next_reconnect_earliest = time.monotonic() + 60.0
    t._must_reconnect = True

    await t.close()

    assert t._reconnect_state is None
    assert t._next_reconnect_earliest == 0.0
    assert t._must_reconnect is False


async def test_transport_failure_without_auto_reconnect(
    base_transport_mock: MagicMock,
) -> None:
    """Test that transport failure when auto_reconnect is disabled closes transport without entering recovery."""
    t = AsyncSmartTransport(
        base_transport_mock,
        auto_reconnect=False,
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )
    base_transport_mock.send_and_receive.side_effect = TimeoutError("stalled")

    with pytest.raises(TimeoutError):
        await t.send_and_receive(1, DummyPDU())

    base_transport_mock.close.assert_awaited_once()
    assert t._must_reconnect is True
    assert t._reconnect_state is None
    assert t._next_reconnect_earliest == 0.0


async def test_transport_failure_handles_close_exception(
    base_transport_mock: MagicMock,
) -> None:
    """Test that an exception during base_transport.close() in failure handling is logged and caught."""
    t = AsyncSmartTransport(
        base_transport_mock,
        response_retry_strategy=AsyncRetrying(stop=stop_after_attempt(1), reraise=True),
    )
    base_transport_mock.send_and_receive.side_effect = TimeoutError("stalled")
    base_transport_mock.close.side_effect = OSError("socket dead")

    with pytest.raises(TimeoutError):
        await t.send_and_receive(1, DummyPDU())

    base_transport_mock.close.assert_awaited_once()
    assert t._must_reconnect is True
    assert t._reconnect_state is not None
