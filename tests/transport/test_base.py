from tmodbus.transport.base import BaseTransport


class _DummyTransport(BaseTransport):
    def __init__(self) -> None:
        self.opened = False
        self.sent = []

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.opened = False

    def is_open(self) -> bool:
        return self.opened

    def send_and_receive(self, slave_id: int, pdu: bytes) -> bytes:
        self.sent.append((slave_id, pdu))
        return b"response"


def test_context_manager():
    t = _DummyTransport()
    with t as tr:
        assert tr.is_open()
    assert not t.is_open()


def test_open_close():
    t = _DummyTransport()
    assert not t.is_open()
    t.open()
    assert t.is_open()
    t.close()
    assert not t.is_open()


def test_send_and_receive():
    t = _DummyTransport()
    t.open()
    resp = t.send_and_receive(1, b"abc")
    assert resp == b"response"
    assert t.sent == [(1, b"abc")]
