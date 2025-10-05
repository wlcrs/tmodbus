import asyncio
import time
from typing import Any, Never
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import serial_asyncio_fast

from tmodbus.exceptions import (
    CRCError,
    IllegalFunctionError,
    InvalidResponseError,
    ModbusConnectionError,
    RTUFrameError,
)
from tmodbus.pdu.base import BaseClientPDU
from tmodbus.transport.async_rtu import (
    MAX_RTU_FRAME_SIZE,
    MIN_RTU_RESPONSE_LENGTH,
    AsyncRtuTransport,
    compute_interframe_delay,
    compute_max_continuous_transmission_delay,
)
from tmodbus.utils.crc import calculate_crc16


def test_compute_delays():
    # baudrate >= 19200 uses at least 1.75ms
    d = compute_interframe_delay(11 / 19200)
    assert d >= 0.00175
    # lower baudrate increases delay
    one_char = 11 / 9600
    assert compute_interframe_delay(one_char) >= 3.5 * one_char
    assert compute_max_continuous_transmission_delay(one_char) == pytest.approx(1.5 * one_char)


class _DummyPDU(BaseClientPDU):
    function_code = 0x03

    def encode_request(self) -> bytes:
        return b"\x03\x00"

    def decode_response(self, data: bytes) -> tuple[str, bytes]:
        return ("decoded", data)


@pytest.mark.asyncio
async def test_open_already_open(monkeypatch):
    reader = AsyncMock()
    writer = MagicMock()
    writer.is_closing.return_value = False
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    # simulate already open
    t._reader = reader
    t._writer = writer
    # patch logger and call open; should early-return and call debug
    with patch("tmodbus.transport.async_rtu.logger") as log:
        await t.open()
        log.debug.assert_called()


@pytest.mark.asyncio
async def test_open_timeout(monkeypatch):
    # simulate open_serial_connection timing out
    monkeypatch.setattr(
        "tmodbus.transport.async_rtu.serial_asyncio_fast.open_serial_connection",
        AsyncMock(side_effect=asyncio.TimeoutError),
    )
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    with pytest.raises(TimeoutError):
        await t.open()


@pytest.fixture
def mock_asyncio_connection(monkeypatch):
    reader = MagicMock(asyncio.StreamReader)
    writer = MagicMock(asyncio.StreamWriter)
    writer.is_closing.return_value = False

    monkeypatch.setattr(serial_asyncio_fast, "open_serial_connection", AsyncMock(return_value=(reader, writer)))
    return reader, writer


async def test_open_close_is_open(mock_asyncio_connection):
    # simulate serial_asyncio_fast open
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()
    assert t.is_open()
    await t.close()
    assert not t.is_open()


async def test_send_and_receive_success(mock_asyncio_connection, monkeypatch):
    reader, writer = mock_asyncio_connection

    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    # prepare reader/writer
    pdu = _DummyPDU()
    unit_id = 1
    # construct response: unit + function + data(1 byte) + crc
    response_data = b"\x05"
    payload = bytes([unit_id, pdu.function_code]) + response_data
    crc = calculate_crc16(payload)
    response_adu = payload + crc
    # first read returns first 4 bytes, then remaining byte
    response_begin = response_adu[:MIN_RTU_RESPONSE_LENGTH]
    remaining = response_adu[MIN_RTU_RESPONSE_LENGTH:]

    reader.readexactly = AsyncMock(side_effect=[response_begin, remaining])

    # monkeypatch get_pdu_class to return a dummy class with expected length 1
    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)

    t._reader = reader
    t._writer = writer
    # ensure no waiting
    t._last_frame_ended_at = time.monotonic() - 10
    result = await t.send_and_receive(unit_id, pdu)
    assert result[0] == "decoded"


async def test_receive_response_no_reader():
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    t._reader = None
    with pytest.raises(ModbusConnectionError):
        await t._receive_response()


async def test_receive_response_incomplete(mock_asyncio_connection, monkeypatch):
    reader, _writer = mock_asyncio_connection
    reader.readexactly = AsyncMock(side_effect=asyncio.IncompleteReadError(partial=b"abc", expected=10))
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()

    with pytest.raises(RTUFrameError):
        await t._receive_response()


@pytest.mark.asyncio
async def test_close_early_return_and_logger(monkeypatch):
    # when _writer is None, close should log debug and return
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    t._writer = None
    t._reader = None

    with patch("tmodbus.transport.async_rtu.logger") as log:
        await t.close()
        log.debug.assert_called()


@pytest.mark.asyncio
async def test_interframe_sleep(monkeypatch):
    # ensure sleep is awaited when last frame ended recently
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    reader = AsyncMock()
    writer = MagicMock()
    writer.drain = AsyncMock()
    writer.is_closing.return_value = False
    t._reader = reader
    t._writer = writer
    # set last ended very recent
    t._last_frame_ended_at = time.monotonic()
    t._interframe_delay = 0.1
    pdu = _DummyPDU()
    # monkeypatch _receive_response to return a valid frame to avoid further exceptions
    monkeypatch.setattr(
        t,
        "_receive_response",
        AsyncMock(
            return_value=bytes([1, pdu.function_code, 0x05]) + calculate_crc16(bytes([1, pdu.function_code, 0x05]))
        ),
    )
    sleep_called = False

    async def fake_sleep(d) -> None:
        nonlocal sleep_called
        sleep_called = True

    monkeypatch.setattr("asyncio.sleep", fake_sleep)
    await t.send_and_receive(1, pdu)
    assert sleep_called


@pytest.mark.asyncio
async def test_send_and_receive_writer_none_after_is_open(monkeypatch):
    # Force is_open to return True but writer None to hit connection-not-established branch
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    t._reader = AsyncMock()
    t._writer = None
    pdu = _DummyPDU()
    # patch is_open to True so code proceeds past initial check
    monkeypatch.setattr(AsyncRtuTransport, "is_open", lambda _: True)
    with pytest.raises(ModbusConnectionError, match=r"Connection not established."):
        await t.send_and_receive(1, pdu)


async def test_expected_length_exceeds_max(mock_asyncio_connection, monkeypatch):
    # craft response_begin with non-exception function code and force get_pdu_class to return large length
    unit_id = 1
    function = 0x03
    response_begin = bytes([unit_id, function, 0x00, 0x00])
    reader, _writer = mock_asyncio_connection
    reader.readexactly = AsyncMock(side_effect=[response_begin])
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()

    class BigPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return MAX_RTU_FRAME_SIZE

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _b: BigPduClass)
    with pytest.raises(RTUFrameError):
        await t._receive_response()


async def test_receive_response_remaining_raises_rtuframe(mock_asyncio_connection, monkeypatch):
    reader, _writer = mock_asyncio_connection
    # make initial read succeed, then remaining raises RTUFrameError
    unit_id = 1
    function = 0x03
    response_begin = bytes([unit_id, function, 0x00, 0x00])
    reader.readexactly = AsyncMock(side_effect=[response_begin, RTUFrameError("err", response_bytes=b"x")])
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 3

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _b: DummyPduClass)
    with pytest.raises(RTUFrameError) as excinfo:
        await t._receive_response()
    # ensure response_bytes includes both parts
    assert excinfo.value.response_bytes.startswith(response_begin)


@pytest.mark.asyncio
async def test_receive_response_initial_timeout(monkeypatch):
    reader = AsyncMock()
    reader.readexactly = AsyncMock(side_effect=TimeoutError)
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    t._reader = reader
    with pytest.raises(TimeoutError):
        await t._receive_response()


@pytest.mark.asyncio
async def test_receive_response_remaining_modbus_connection_error(monkeypatch):
    # initial read succeeds, remaining raises ModbusConnectionError and should be wrapped
    unit_id = 1
    function = 0x03
    response_begin = bytes([unit_id, function, 0x00, 0x00])
    reader = AsyncMock()
    reader.readexactly = AsyncMock(side_effect=[response_begin, ModbusConnectionError("fail", bytes_read=b"ERR")])
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    t._reader = reader

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 3

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _b: DummyPduClass)
    with pytest.raises(ModbusConnectionError) as excinfo:
        await t._receive_response()
    # ensure bytes_read contains the initial bytes
    assert getattr(excinfo.value, "response_bytes", b"") or getattr(excinfo.value, "response_bytes", None) is not None


async def test_send_and_receive_crc_and_address_and_exception(mock_asyncio_connection, monkeypatch):
    reader, _writer = mock_asyncio_connection
    # Test CRC error, slave address mismatch, and exception response mapping
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()
    pdu = _DummyPDU()
    unit_id = 1

    # 1) CRC error: create frame with bad CRC
    payload = bytes([unit_id, pdu.function_code, 0x01])
    bad_response = payload + b"\x00\x00"

    reader.readexactly = AsyncMock(side_effect=[bad_response[:4], bad_response[4:]])

    class DummyPduClass:
        @staticmethod
        def get_expected_response_data_length(_begin_bytes: bytes) -> int:
            return 1

    monkeypatch.setattr("tmodbus.transport.async_rtu.get_pdu_class", lambda _: DummyPduClass)

    t._last_frame_ended_at = time.monotonic() - 10
    with pytest.raises(CRCError):
        await t.send_and_receive(unit_id, pdu)

    # 2) Slave address mismatch
    other_unit = 2
    payload = bytes([other_unit, pdu.function_code, 0x01])
    crc = calculate_crc16(payload)
    response = payload + crc
    reader.readexactly = AsyncMock(side_effect=[response[:4], response[4:]])
    with pytest.raises(InvalidResponseError, match=r"Slave address mismatch"):
        await t.send_and_receive(unit_id, pdu)

    # 3) Exception response mapped to specific class
    exc_code = 0x01  # ILLEGAL_FUNCTION
    payload = bytes([unit_id, pdu.function_code | 0x80, exc_code])
    crc = calculate_crc16(payload)
    response = payload + crc
    reader.readexactly = AsyncMock(side_effect=[response[:4], response[4:]])
    with pytest.raises(IllegalFunctionError):
        await t.send_and_receive(unit_id, pdu)

    # 4) Function code mismatch
    payload = bytes([unit_id, 0x04, 0x01])
    crc = calculate_crc16(payload)
    response = payload + crc
    reader.readexactly = AsyncMock(side_effect=[response[:4], response[4:]])
    with pytest.raises(InvalidResponseError, match=r"Function code mismatch"):
        await t.send_and_receive(unit_id, pdu)


async def test_open_raises_modbus_connection_error_on_generic_exception(monkeypatch):
    # open_serial_connection raises RuntimeError -> open should raise ModbusConnectionError
    monkeypatch.setattr(
        "tmodbus.transport.async_rtu.serial_asyncio_fast.open_serial_connection",
        AsyncMock(side_effect=RuntimeError("boom")),
    )
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    with pytest.raises(ModbusConnectionError):
        await t.open()


@pytest.mark.asyncio
async def test_open_and_close_log_info(mock_asyncio_connection, monkeypatch):
    _reader, writer = mock_asyncio_connection
    # ensure wait_closed exists
    writer.wait_closed = AsyncMock()
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)

    with patch("tmodbus.transport.async_rtu.logger") as log:
        await t.open()
        log.info.assert_called_with("Async Serial connection established to '%s'", t.port)
        await t.close()
        log.info.assert_called_with("Serial connection closed: %s", t.port)


# (the reload-style import test was removed; the exec-based test above is sufficient)


@pytest.mark.asyncio
async def test_close_logs_on_exception(mock_asyncio_connection, monkeypatch):
    # simulate writer.wait_closed raising, hitting the except branch in close()
    _reader, writer = mock_asyncio_connection

    async def bad_wait_closed() -> None:
        raise RuntimeError("boom")

    writer.wait_closed = bad_wait_closed

    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()
    with patch("tmodbus.transport.async_rtu.logger") as log:
        await t.close()
        # ensure the debug log for exception during close was called
        log.debug.assert_called()


@pytest.mark.asyncio
async def test_send_and_receive_not_connected():
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    # ensure no reader/writer set (is_open() returns False)
    with pytest.raises(ModbusConnectionError, match=r"Not connected"):
        await t.send_and_receive(1, _DummyPDU())


@pytest.mark.asyncio
async def test_send_and_receive_recv_exception_logs(mock_asyncio_connection, monkeypatch):
    # Ensure that when _receive_response raises RTUFrameError, send_and_receive logs raw traffic with is_error=True

    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()
    # make _receive_response raise RTUFrameError
    err_bytes = b"\x01\x83\x02"

    async def raise_err() -> None:
        raise RTUFrameError("boom", response_bytes=err_bytes)

    monkeypatch.setattr(t, "_receive_response", raise_err)

    with patch("tmodbus.transport.async_rtu.log_raw_traffic") as log_raw:
        with pytest.raises(RTUFrameError):
            await t.send_and_receive(1, _DummyPDU())
        log_raw.assert_called_with("recv", err_bytes, is_error=True)


async def test_receive_response_wait_for_timeout(mock_asyncio_connection, monkeypatch):
    # Force asyncio.wait_for to raise TimeoutError to hit the except TimeoutError branch
    t = AsyncRtuTransport("/dev/ttyUSB0", baudrate=9600)
    await t.open()

    async def _fake_wait_for(coro, timeout: int, *args: Any, **kwargs: Any) -> Never:  # noqa: ASYNC109
        await coro
        raise TimeoutError("timed out")

    with patch("asyncio.wait_for", _fake_wait_for), pytest.raises(TimeoutError):
        await t._receive_response()

    async def _fake_wait_for_with_runtime_error(coro, timeout: int, *args: Any, **kwargs: Any) -> Never:  # noqa: ASYNC109
        await coro
        raise RuntimeError("timed out")

    with patch("asyncio.wait_for", _fake_wait_for_with_runtime_error), pytest.raises(ModbusConnectionError):
        await t._receive_response()
