"""Tests for tmodbus/transport/base.py ."""

from tmodbus.transport.base import BaseTransport


class _DummyTransport(BaseTransport):
    def __init__(self) -> None:
        self.opened = False
        self.sent: list[tuple[int, bytes]] = []

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.opened = False

    def is_open(self) -> bool:
        return self.opened

    def send_and_receive(self, slave_id: int, pdu: bytes) -> bytes:
        self.sent.append((slave_id, pdu))
        return b"response"


def test_context_manager() -> None:
    """Test context manager functionality."""
    t = _DummyTransport()
    with t as tr:
        assert tr.is_open()
    assert not t.is_open()


def test_open_close() -> None:
    """Test open and close functionality."""
    t = _DummyTransport()
    assert not t.is_open()
    t.open()
    assert t.is_open()
    t.close()
    assert not t.is_open()


def test_send_and_receive() -> None:
    """Test send and receive functionality."""
    t = _DummyTransport()
    t.open()
    resp = t.send_and_receive(1, b"abc")
    assert resp == b"response"
    assert t.sent == [(1, b"abc")]
