import asyncio
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from tmodbus.exceptions import InvalidResponseError, ModbusConnectionError, ModbusResponseError
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_tcp import AsyncTcpTransport


class _DummyPDU(BaseClientPDU):
    def encode_request(self) -> bytes:
        return b"\x03\x04"

    def decode_response(self, data: bytes) -> tuple[str, bytes]:
        return ("decoded", data)


async def test_invalid_constructor_args() -> None:
    with pytest.raises(ValueError, match=r"Port must be .*"):
        AsyncTcpTransport("host", port=0)
    with pytest.raises(ValueError, match=r"Timeout must .*"):
        AsyncTcpTransport("host", timeout=0)
    with pytest.raises(ValueError, match=r"Connect timeout must .*"):
        AsyncTcpTransport("host", connect_timeout=0)


async def test_open_and_close(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = AsyncMock()
    writer = MagicMock()
    writer.is_closing.return_value = False
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    assert t.is_open()
    await t.close()
    assert not t.is_open()


async def test_open_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(side_effect=Exception("fail")))
    t = AsyncTcpTransport("host", port=1234)
    with pytest.raises(ModbusConnectionError):
        await t.open()


async def test_is_open_false_when_not_connected() -> None:
    t = AsyncTcpTransport("host", port=1234)
    assert not t.is_open()


async def test_transaction_id_wraparound() -> None:
    t = AsyncTcpTransport("host", port=1234)
    t._next_transaction_id = 0xFFFF
    tid1 = t._get_transaction_id()
    tid2 = t._get_transaction_id()
    assert tid1 == 0xFFFF
    assert tid2 == 0


@pytest.fixture
def mock_asyncio_connection(monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, MagicMock]:
    reader = MagicMock(asyncio.StreamReader)
    writer = MagicMock(asyncio.StreamWriter)
    writer.is_closing.return_value = False

    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(return_value=(reader, writer)))
    return reader, writer


async def test_send_and_receive_success(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, _writer = mock_asyncio_connection

    # MBAP header: tid=1, pid=0, len=3, uid=1
    mbap = b"\x00\x01\x00\x00\x00\x03\x01"
    pdu_bytes = b"\x03\x04"
    reader.readexactly = AsyncMock(side_effect=[mbap, pdu_bytes])
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    pdu = _DummyPDU()
    result = await t.send_and_receive(1, pdu)
    assert result == ("decoded", pdu_bytes)


async def test_send_and_receive_not_connected() -> None:
    t = AsyncTcpTransport("host", port=1234)
    pdu = _DummyPDU()
    with pytest.raises(ModbusConnectionError):
        await t.send_and_receive(1, pdu)


async def test_do_send_and_receive_invalid_tid(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, _writer = mock_asyncio_connection
    # MBAP header: tid=2 (should be 1), pid=0, len=3, uid=1
    mbap = b"\x00\x02\x00\x00\x00\x03\x01"
    pdu_bytes = b"\x03\x04"
    reader.readexactly = AsyncMock(side_effect=[mbap, pdu_bytes])
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    pdu = _DummyPDU()
    with pytest.raises(InvalidResponseError):
        await t.send_and_receive(1, pdu)


async def test_do_send_and_receive_exception_response(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, _writer = mock_asyncio_connection
    # MBAP header: tid=1, pid=0, len=3, uid=1
    mbap = b"\x00\x01\x00\x00\x00\x03\x01"
    # Exception response: first byte 0x83 (0x03 | 0x80), second byte is exception code 1
    response_pdu = b"\x83\x01"
    reader.readexactly = AsyncMock(side_effect=[mbap, response_pdu])
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    pdu = _DummyPDU()
    with pytest.raises(ModbusResponseError):
        await t.send_and_receive(1, pdu)


async def test_receive_exact_timeout(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, _writer = mock_asyncio_connection
    reader.readexactly = AsyncMock(side_effect=asyncio.TimeoutError)
    t = AsyncTcpTransport("host", port=1234)
    t._reader = reader
    t.timeout = 0.01
    with pytest.raises(TimeoutError):
        await t._receive_exact(5)


async def test_receive_exact_incomplete(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, _writer = mock_asyncio_connection
    reader.readexactly = AsyncMock(side_effect=asyncio.IncompleteReadError(partial=b"abc", expected=5))
    t = AsyncTcpTransport("host", port=1234)
    t._reader = reader
    with pytest.raises(ModbusConnectionError):
        await t._receive_exact(5)


@pytest.mark.usefixtures("mock_asyncio_connection")
async def test_open_already_open() -> None:
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    # Should early return and log if already open
    with patch("tmodbus.transport.async_tcp.logger") as log:
        await t.open()
        log.debug.assert_called()


async def test_close_already_closed() -> None:
    t = AsyncTcpTransport("host", port=1234)
    # Should early return and log if already closed
    with patch("tmodbus.transport.async_tcp.logger") as log:
        await t.close()
        log.debug.assert_called()


async def test_open_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(side_effect=asyncio.TimeoutError))
    t = AsyncTcpTransport("host", port=1234)
    with patch("tmodbus.transport.async_tcp.logger") as log:
        with pytest.raises(asyncio.TimeoutError):
            await t.open()
        log.warning.assert_called()


async def test_open_other_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(side_effect=RuntimeError("fail")))
    t = AsyncTcpTransport("host", port=1234)
    with patch("tmodbus.transport.async_tcp.logger") as log:
        with pytest.raises(ModbusConnectionError):
            await t.open()
        log.exception.assert_called()


async def test_close_exception(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    _reader, writer = mock_asyncio_connection
    writer.close.side_effect = Exception("fail")
    writer.wait_closed = AsyncMock()
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    with patch("tmodbus.transport.async_tcp.logger") as log:
        await t.close()
        log.debug.assert_called()
    assert t._writer is None
    assert t._reader is None


async def test_do_send_and_receive_invalid_protocol_id(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, _writer = mock_asyncio_connection
    # MBAP header: tid=1, pid=1 (should be 0), len=3, uid=1
    mbap = b"\x00\x01\x00\x01\x00\x03\x01"
    response_pdu = b"\x11\x22"
    reader.readexactly = AsyncMock(side_effect=[mbap, response_pdu])
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    pdu = _DummyPDU()
    with pytest.raises(InvalidResponseError, match="Invalid Protocol ID"):
        await t.send_and_receive(1, pdu)


async def test_do_send_and_receive_invalid_unit_id(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, _writer = mock_asyncio_connection
    # MBAP header: tid=1, pid=0, len=3, uid=2 (should be 1)
    mbap = b"\x00\x01\x00\x00\x00\x03\x02"
    response_pdu = b"\x11\x22"
    reader.readexactly = AsyncMock(side_effect=[mbap, response_pdu])
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    pdu = _DummyPDU()
    with pytest.raises(InvalidResponseError, match="Unit ID mismatch"):
        await t.send_and_receive(1, pdu)


async def test_do_send_and_receive_invalid_pdu_length(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, _writer = mock_asyncio_connection
    # MBAP header: tid=1, pid=0, len=0, uid=1 (pdu_length = -1)
    mbap = b"\x00\x01\x00\x00\x00\x00\x01"
    reader.readexactly = AsyncMock(return_value=mbap)
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    pdu = _DummyPDU()
    with pytest.raises(InvalidResponseError, match="Invalid PDU length"):
        await t.send_and_receive(1, pdu)


async def test_do_send_and_receive_incomplete_read_error(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, writer = mock_asyncio_connection
    writer.drain = AsyncMock()
    # MBAP header: tid=1, pid=0, len=3, uid=1
    mbap = b"\x00\x01\x00\x00\x00\x03\x01"

    reader.readexactly = AsyncMock(side_effect=[mbap, asyncio.IncompleteReadError(partial=b"err", expected=5)])
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    pdu = _DummyPDU()
    with patch("tmodbus.transport.async_tcp.log_raw_traffic") as log:
        with pytest.raises(ModbusConnectionError):
            await t.send_and_receive(1, pdu)
        log.assert_called_with("recv", b"err", is_error=True)


async def test_receive_exact_other_exception(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    reader, _writer = mock_asyncio_connection
    reader.readexactly = AsyncMock(side_effect=RuntimeError("fail"))

    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    with pytest.raises(ModbusConnectionError, match="Failed to read"):
        await t._receive_exact(5)

    t._reader = None
    with pytest.raises(ModbusConnectionError, match="Connection not established"):
        await t._receive_exact(5)


async def test_close_during_send_and_receive() -> None:
    t = AsyncTcpTransport("host", port=1234)
    t._writer = None
    with patch.object(t, "is_open", return_value=True):
        pdu = _DummyPDU()
        with pytest.raises(ModbusConnectionError):
            await t.send_and_receive(1, pdu)


async def test_close_logs_info(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    _reader, writer = mock_asyncio_connection
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    with patch("tmodbus.transport.async_tcp.logger") as log:
        await t.close()
        log.info.assert_called_with("Async TCP connection closed: %s:%d", t.host, t.port)


async def test_close_exception_logs(mock_asyncio_connection: tuple[MagicMock, MagicMock]) -> None:
    _reader, writer = mock_asyncio_connection
    writer.close.side_effect = Exception("fail")
    writer.wait_closed = AsyncMock()
    t = AsyncTcpTransport("host", port=1234)
    await t.open()
    with patch("tmodbus.transport.async_tcp.logger") as log:
        await t.close()
        log.debug.assert_called_with("Error during async connection close (ignorable): %s", ANY)
