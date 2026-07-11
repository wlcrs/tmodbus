"""Tests for tmodbus/server/async_ascii.py."""

import asyncio
from unittest.mock import patch

import pytest
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteMultipleRegistersPDU
from tmodbus.server import AsyncAsciiServer, ModbusRequestRouter
from tmodbus.utils.lrc import calculate_lrc

pytestmark = pytest.mark.usefixtures("patch_serial")


class MockSerial:
    """Mock implementation of serialx.Serial using asyncio.Queue."""

    def __init__(self, port: str, baudrate: int = 19200, **kwargs: object) -> None:
        """Initialize the MockSerial."""
        self.port = port
        self.baudrate = baudrate
        self.kwargs = kwargs
        self.read_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.write_calls: list[bytes] = []
        self._is_open = False

    def open(self) -> None:
        """Open the serial port."""
        self._is_open = True

    def close(self) -> None:
        """Close the serial port."""
        self._is_open = False

    async def read(self) -> bytes:
        """Read data from the serial port."""
        return await self.read_queue.get()

    async def write(self, data: bytes) -> None:
        """Write data to the serial port."""
        self.write_calls.append(data)


@pytest.fixture
def patch_serial() -> type[MockSerial]:
    """Fixture to patch the Serial class with our MockSerial."""
    with patch("tmodbus.server.async_ascii.Serial", new=MockSerial) as mock_cls:
        yield mock_cls  # type: ignore[yield-type]


async def test_ascii_server_happy_path() -> None:
    """Test successful request/response transaction on the ASCII server."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0xABCD]

    server = AsyncAsciiServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = server._serial
    assert mock_serial_inst is not None

    # Build ASCII frame: unit_id=1, fc=3, start_address=0, quantity=1
    bin_data = b"\x01\x03\x00\x00\x00\x01"
    lrc = calculate_lrc(bin_data)
    frame = b":" + (bin_data + bytes([lrc])).hex().upper().encode("ascii") + b"\r\n"

    for b in frame:
        await mock_serial_inst.read_queue.put(bytes([b]))

    await asyncio.sleep(0.05)

    assert len(mock_serial_inst.write_calls) == 1
    resp = mock_serial_inst.write_calls[0]
    # Expected ASCII response frame starting with ":" and ending with "\r\n"
    assert resp.startswith(b":")
    assert resp.endswith(b"\r\n")

    # Decode hex response:
    resp_hex = resp[1:-2].decode("ascii")
    resp_bin = bytes.fromhex(resp_hex)
    assert resp_bin[0] == 1  # unit_id
    assert resp_bin[1] == 3  # fc
    assert resp_bin[2] == 2  # byte count
    assert resp_bin[3:5] == b"\xab\xcd"

    await server.stop()


async def test_ascii_server_buffer_overrun_dos() -> None:
    """Test that ASCII server clears buffer if it grows too large without delimiters (DoS validation)."""
    router = ModbusRequestRouter()

    server = AsyncAsciiServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = server._serial
    assert mock_serial_inst is not None

    # Send 514 bytes of data without ":" or "\r\n"
    overrun_data = b"A" * 514
    for b in overrun_data:
        await mock_serial_inst.read_queue.put(bytes([b]))

    await asyncio.sleep(0.05)

    # Server should clear buffer, no crash and no response
    assert len(mock_serial_inst.write_calls) == 0

    # Verify server is still functional by sending a valid frame
    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x1111]

    bin_data = b"\x01\x03\x00\x00\x00\x01"
    lrc = calculate_lrc(bin_data)
    frame = b":" + (bin_data + bytes([lrc])).hex().upper().encode("ascii") + b"\r\n"

    for b in frame:
        await mock_serial_inst.read_queue.put(bytes([b]))

    await asyncio.sleep(0.05)
    assert len(mock_serial_inst.write_calls) == 1

    await server.stop()


async def test_ascii_server_invalid_hex() -> None:
    """Test that ASCII server discards frames with invalid hex characters."""
    router = ModbusRequestRouter()

    server = AsyncAsciiServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = server._serial
    assert mock_serial_inst is not None

    # Contains 'G' which is invalid hex
    frame = b":01030000000GFA\r\n"
    with patch("tmodbus.server.async_ascii.log_raw_traffic") as mock_log:
        await mock_serial_inst.read_queue.put(frame)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", frame, is_error=True)

    assert len(mock_serial_inst.write_calls) == 0

    await server.stop()


async def test_ascii_server_short_frame() -> None:
    """Test that ASCII server discards short frames."""
    router = ModbusRequestRouter()

    server = AsyncAsciiServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = server._serial
    assert mock_serial_inst is not None

    # Less than 9 characters
    frame = b":0103FA\r\n"
    with patch("tmodbus.server.async_ascii.log_raw_traffic") as mock_log:
        await mock_serial_inst.read_queue.put(frame)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", frame, is_error=True)

    assert len(mock_serial_inst.write_calls) == 0

    await server.stop()


async def test_ascii_server_invalid_lrc() -> None:
    """Test that ASCII server discards frames with invalid LRC."""
    router = ModbusRequestRouter()

    server = AsyncAsciiServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = server._serial
    assert mock_serial_inst is not None

    # LRC should be FA, sending 00 instead
    frame = b":01030000000100\r\n"
    with patch("tmodbus.server.async_ascii.log_raw_traffic") as mock_log:
        await mock_serial_inst.read_queue.put(frame)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", frame, is_error=True)

    assert len(mock_serial_inst.write_calls) == 0

    await server.stop()


async def test_ascii_server_raw_traffic_logging() -> None:
    """Test that ASCII server logs raw traffic with is_error=True on errors."""
    router = ModbusRequestRouter()
    server = AsyncAsciiServer(port="/dev/ttyUSB0", handler=router)
    await server.start()
    mock_serial_inst = server._serial
    assert mock_serial_inst is not None

    with patch("tmodbus.server.async_ascii.log_raw_traffic") as mock_log:
        # 1. Discarding garbage data before ':'
        # Send garbage 'xyz'
        await mock_serial_inst.read_queue.put(b"xyz")
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", b"xyz", is_error=True)

        # 2. Invalid LRC
        mock_log.reset_mock()
        frame = b":01030000000100\r\n"
        await mock_serial_inst.read_queue.put(frame)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", frame, is_error=True)

        # 3. Buffer exceeded maximum frame size
        mock_log.reset_mock()
        garbage_large = b"a" * 515
        await mock_serial_inst.read_queue.put(garbage_large)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", garbage_large, is_error=True)

    # 4. Residual bytes on stop
    await mock_serial_inst.read_queue.put(b":01")  # uncompleted frame
    await asyncio.sleep(0.05)
    with patch("tmodbus.server.async_ascii.log_raw_traffic") as mock_log:
        await server.stop()
        mock_log.assert_any_call("recv", b":01", is_error=True)


async def test_ascii_server_double_stop_and_serve_forever() -> None:
    """Test serve_forever and double stop on AsyncAsciiServer."""
    router = ModbusRequestRouter()
    ascii_srv = AsyncAsciiServer(port="/dev/ttyUSB0", handler=router)
    await ascii_srv.stop()  # Stop before starting
    task = asyncio.create_task(ascii_srv.serve_forever())
    await asyncio.sleep(0.05)
    task.cancel()
    await task
    await ascii_srv.stop()  # Second stop


async def test_ascii_server_edge_cases() -> None:
    """Cover edge cases in AsyncAsciiServer."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [1]

    @router.register(WriteMultipleRegistersPDU)
    async def handle_write_multiple(_unit_id: int, _request: WriteMultipleRegistersPDU) -> int:
        server._serial = None
        return 1

    server = AsyncAsciiServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = server._serial
    assert mock_serial_inst is not None

    # Test "if not data: continue" in ASCII serve loop
    await mock_serial_inst.read_queue.put(b"")
    await asyncio.sleep(0.02)

    # Test ASCII buffer overflow (> 513 bytes)
    await mock_serial_inst.read_queue.put(b"A" * 515)
    await asyncio.sleep(0.05)

    # Colon character not in buffer
    await mock_serial_inst.read_queue.put(b"ABC\r\n")
    await asyncio.sleep(0.05)

    # Colon character in buffer but '\r\n' missing
    await mock_serial_inst.read_queue.put(b":0103")
    await asyncio.sleep(0.05)
    # Flush incomplete frame
    await mock_serial_inst.read_queue.put(b"\r\n")
    await asyncio.sleep(0.05)

    # Leading garbage before ':' (triggers start_idx > 0 branch in ASCII frame extraction)
    # LRC of b"\x01\x03\x00\x00\x00\x01" is 0xFB
    await mock_serial_inst.read_queue.put(b"GARBAGE:010300000001FB\r\n")
    await asyncio.sleep(0.05)
    assert len(mock_serial_inst.write_calls) == 1
    mock_serial_inst.write_calls.clear()

    # Short frame (length < 9)
    await mock_serial_inst.read_queue.put(b":01\r\n")
    await asyncio.sleep(0.05)

    # Sub-function PDU missing subfunction code
    # LRC of b"\x01\x2b" is 0xD4
    frame1 = b":012BD4\r\n"
    await mock_serial_inst.read_queue.put(frame1)
    await asyncio.sleep(0.05)

    # Valid sub-function code (fc=43, sub=14)
    # Encapsulated Interface Transport (0x2B), mei_type=14 (0x0E), read_device_id=1, object_id=0
    # bin_data = b"\x01\x2b\x0e\x01\x00", LRC = 0xC5
    frame_good_sub = b":012B0E0100C5\r\n"
    await mock_serial_inst.read_queue.put(frame_good_sub)
    await asyncio.sleep(0.05)

    # Invalid sub-function code (fc=43, sub=0)
    # bin_data = b"\x01\x2b\x00\x01\x00", LRC = 0xD3
    frame_bad_sub = b":012B000100D3\r\n"
    await mock_serial_inst.read_queue.put(frame_bad_sub)
    await asyncio.sleep(0.05)

    # Invalid PDU parameters: quantity = 0 (raises InvalidRequestError in decode_request)
    # bin_data = b"\x01\x03\x00\x00\x00\x00", LRC = 0xFC
    frame_invalid_param = b":010300000000FC\r\n"
    await mock_serial_inst.read_queue.put(frame_invalid_param)
    await asyncio.sleep(0.05)
    # Write calls: 1 (missing sub) + 1 (good sub) + 1 (bad sub) + 1 (invalid param) = 4
    assert len(mock_serial_inst.write_calls) == 4
    mock_serial_inst.write_calls.clear()

    # 1. Serial port read exception in loop (run while loop is still active!)
    with patch.object(mock_serial_inst, "read", side_effect=RuntimeError("Serial Read Failure")):
        await mock_serial_inst.read_queue.put(b":0103")
        await asyncio.sleep(0.15)

    # 2. Trigger WriteMultipleRegistersPDU to unset server._serial inside handler
    # LRC of b"\x01\x10\x00\x00\x00\x01\x02\x00\x01" is 0xEB
    frame_term = b":011000000001020001EB\r\n"
    await mock_serial_inst.read_queue.put(frame_term)
    await asyncio.sleep(0.15)
    assert len(mock_serial_inst.write_calls) == 0

    await server.stop()


async def test_ascii_server_read_exception_empty_buffer() -> None:
    """Test ASCII server exception handling when buffer is empty."""
    router = ModbusRequestRouter()
    server = AsyncAsciiServer(port="/dev/ttyUSB0", handler=router)
    with patch.object(MockSerial, "read", side_effect=RuntimeError("Serial Read Failure")):
        await server.start()
        await asyncio.sleep(0.15)
        await server.stop()
