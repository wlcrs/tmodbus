"""Tests for tmodbus/transport/async_base.py ."""

from typing import TypeVar

from tmodbus.pdu import BasePDU
from tmodbus.transport.async_base import AsyncBaseTransport

RT = TypeVar("RT")

DUMMY_RESPONSE = "dummy_response"


class DummyAsyncTransport(AsyncBaseTransport):
    """A dummy async transport for testing purposes."""

    performed_actions: list[str | list[str | int]]  # Actions performed by the transport
    opened: bool  # Indicates if the transport is open

    def __init__(self) -> None:
        """Initialize the dummy transport."""
        self.performed_actions = []
        self.opened = False

    async def open(self) -> None:
        """Open the transport connection."""
        self.performed_actions.append("open")
        self.opened = True

    async def close(self) -> None:
        """Close the transport connection."""
        self.performed_actions.append("close")
        self.opened = False

    def is_open(self) -> bool:
        """Check if the transport connection is open."""
        self.performed_actions.append("is_open")
        return self.opened

    async def send_and_receive(self, unit_id: int, pdu: BasePDU[RT]) -> RT:  # type: ignore[override]
        """Send a PDU and receive a response."""
        self.performed_actions.append(["send_and_receive", unit_id, type(pdu).__name__])
        # For testing, just return None
        return DUMMY_RESPONSE  # type: ignore[return-value]


async def test_async_base_transport_context_manager() -> None:
    """Test that AsyncBaseTransport can be used as a context manager."""
    transport = DummyAsyncTransport()

    async with transport:
        assert transport.is_open()
        assert "open" in transport.performed_actions

    assert not transport.is_open()
    assert "close" in transport.performed_actions


def test_notify_connection_lost_no_callback() -> None:
    """_notify_connection_lost is a no-op when no callback is registered."""
    transport = DummyAsyncTransport()
    assert transport.on_connection_lost is None

    # Should not raise.
    transport._notify_connection_lost(None)


def test_notify_connection_lost_invokes_callback() -> None:
    """_notify_connection_lost forwards the causing exception to the callback."""
    calls: list[Exception | None] = []
    transport = DummyAsyncTransport()
    transport.on_connection_lost = calls.append

    error = RuntimeError("dropped")
    transport._notify_connection_lost(error)

    assert calls == [error]


def test_notify_connection_lost_swallows_callback_error() -> None:
    """A raising callback must not propagate out of _notify_connection_lost."""

    def boom(_exc: Exception | None) -> None:
        msg = "callback failed"
        raise ValueError(msg)

    transport = DummyAsyncTransport()
    transport.on_connection_lost = boom

    # Should not raise.
    transport._notify_connection_lost(None)
