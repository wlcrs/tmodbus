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
