"""Tests for tmodbus/server/async_rtu.py."""

import asyncio
from collections.abc import Iterator
from typing import cast
from unittest.mock import patch

import pytest
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteMultipleCoilsPDU, WriteMultipleRegistersPDU
from tmodbus.server import AsyncRtuServer, ModbusRequestRouter
from tmodbus.utils.crc import calculate_crc16

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

    async def read(self, _n: int | None = None) -> bytes:
        """Read data from the serial port. Accepts an optional size arg."""
        return await self.read_queue.get()

    def write(self, data: bytes) -> None:
        """Write data to the serial port (synchronous for writer-like API)."""
        self.write_calls.append(data)

    async def drain(self) -> None:
        """No-op drain for writer compatibility."""
        return


@pytest.fixture
def patch_serial() -> Iterator[type[MockSerial]]:
    """Fixture to patch the Serial class with our MockSerial."""

    async def fake_open_serial_connection(
        url: str | None, baudrate: int = 19200, **kwargs: object
    ) -> tuple[MockSerial, MockSerial]:
        inst = MockSerial(url or "", baudrate=baudrate, **kwargs)
        return inst, inst

    with patch("tmodbus.server.async_rtu.open_serial_connection", new=fake_open_serial_connection):
        yield MockSerial


async def test_rtu_server_happy_path() -> None:
    """Test successful request/response transaction on the RTU server."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x7777]

    server = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = cast("MockSerial", server._reader)
    assert mock_serial_inst is not None

    # Feed a valid RTU frame: unit_id=1, fc=3, start_address=0, quantity=1
    pdu = b"\x01\x03\x00\x00\x00\x01"
    crc = calculate_crc16(pdu)
    for b in pdu + crc:
        await mock_serial_inst.read_queue.put(bytes([b]))

    # Give loop a moment to process
    await asyncio.sleep(0.05)

    assert len(mock_serial_inst.write_calls) == 1
    resp = mock_serial_inst.write_calls[0]
    assert resp[0] == 1
    assert resp[1] == 3
    assert resp[2] == 2  # byte count
    assert resp[3:5] == b"\x77\x77"

    await server.stop()


async def test_rtu_server_invalid_crc() -> None:
    """Test that RTU server ignores frames with invalid CRC."""
    router = ModbusRequestRouter()

    server = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = cast("MockSerial", server._reader)
    assert mock_serial_inst is not None

    # Send PDU with invalid CRC (b"\x00\x00")
    pdu = b"\x01\x03\x00\x00\x00\x01"
    frame = pdu + b"\x00\x00"
    with patch("tmodbus.server.async_rtu.log_raw_traffic") as mock_log:
        await mock_serial_inst.read_queue.put(frame)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", frame, is_error=True)

    # No response should be written
    assert len(mock_serial_inst.write_calls) == 0

    await server.stop()


async def test_rtu_server_unsupported_function_code() -> None:
    """Test that RTU server clears buffer on unsupported function code and stays functional."""
    router = ModbusRequestRouter()

    server = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = cast("MockSerial", server._reader)
    assert mock_serial_inst is not None

    # Send unsupported function code 0x99 as a single chunk
    pdu_bad = b"\x01\x99\x00\x00\x00\x01"
    crc_bad = calculate_crc16(pdu_bad)
    frame_bad = pdu_bad + crc_bad
    with patch("tmodbus.server.async_rtu.log_raw_traffic") as mock_log:
        await mock_serial_inst.read_queue.put(frame_bad)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", frame_bad, is_error=True)

    # Buffer should be cleared, no response sent (we don't know frame length to respond safely)
    assert len(mock_serial_inst.write_calls) == 0

    # Verify server is still functional by sending a valid frame
    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x5555]

    pdu_good = b"\x01\x03\x00\x00\x00\x01"
    crc_good = calculate_crc16(pdu_good)
    with patch("tmodbus.server.async_rtu.log_raw_traffic") as mock_log:
        await mock_serial_inst.read_queue.put(pdu_good + crc_good)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", pdu_good + crc_good, is_error=False, is_ignored=False)

    assert len(mock_serial_inst.write_calls) == 1
    assert mock_serial_inst.write_calls[0][3:5] == b"\x55\x55"

    await server.stop()


async def test_rtu_server_frame_too_large() -> None:
    """Test that RTU server clears buffer when expected frame size is too large (DoS validation)."""
    router = ModbusRequestRouter()

    server = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = cast("MockSerial", server._reader)
    assert mock_serial_inst is not None

    # Send Write Multiple Registers function code 16 with huge payload count (exceeding MAX_RTU_FRAME_SIZE)
    pdu = b"\x01\x10\x00\x00\x00\xfa\xfb"  # quantity=250, byte_count=251
    with patch("tmodbus.server.async_rtu.log_raw_traffic") as mock_log:
        await mock_serial_inst.read_queue.put(pdu)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", pdu, is_error=True)

    # Server should clear buffer and send nothing
    assert len(mock_serial_inst.write_calls) == 0

    await server.stop()


async def test_rtu_server_raw_traffic_logging() -> None:
    """Test that RTU server logs raw traffic with is_error=True on errors."""
    router = ModbusRequestRouter()
    server = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    await server.start()
    mock_serial_inst = cast("MockSerial", server._reader)
    assert mock_serial_inst is not None

    with patch("tmodbus.server.async_rtu.log_raw_traffic") as mock_log:
        # 1. Invalid frame length (ValueError in parsing)
        # FC 16 with huge payload count
        pdu = b"\x01\x10\x00\x00\x00\xfa\xfb"
        await mock_serial_inst.read_queue.put(pdu)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", pdu, is_error=True)

        # 2. Bad CRC
        mock_log.reset_mock()
        pdu_bad_crc = b"\x01\x03\x00\x00\x00\x01\x00\x00"  # Incorrect CRC
        await mock_serial_inst.read_queue.put(pdu_bad_crc)
        await asyncio.sleep(0.05)
        mock_log.assert_any_call("recv", pdu_bad_crc, is_error=True)

    # 3. Residual bytes on stop
    await mock_serial_inst.read_queue.put(b"\x01\x03")  # Incomplete frame
    await asyncio.sleep(0.05)
    with patch("tmodbus.server.async_rtu.log_raw_traffic") as mock_log:
        await server.stop()
        mock_log.assert_any_call("recv", b"\x01\x03", is_error=True)


async def test_rtu_server_double_stop_and_serve_forever() -> None:
    """Test serve_forever and double stop on AsyncRtuServer."""
    router = ModbusRequestRouter()
    rtu = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    await rtu.stop()  # Stop before starting
    task = asyncio.create_task(rtu.serve_forever())
    await asyncio.sleep(0.05)
    task.cancel()
    await task
    await rtu.stop()  # Second stop


async def test_rtu_server_edge_cases() -> None:  # noqa: PLR0915
    """Cover edge cases in AsyncRtuServer."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [1]

    @router.register(WriteMultipleCoilsPDU)
    async def handle_write_coils(_unit_id: int, _request: WriteMultipleCoilsPDU) -> int:
        return 8

    @router.register(WriteMultipleRegistersPDU)
    async def handle_write_multiple(_unit_id: int, _request: WriteMultipleRegistersPDU) -> int:
        # Terminate loop by clearing the reader/writer so serve loop exits
        server._reader = None
        server._writer = None
        return 1

    server = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = cast("MockSerial", server._reader)
    assert mock_serial_inst is not None

    # Test "if not data: continue" in RTU serve loop
    await mock_serial_inst.read_queue.put(b"")
    await asyncio.sleep(0.02)

    # Fragmented frame transmission: send only 2 bytes initially (hits "else: return None" in length parsing)
    await mock_serial_inst.read_queue.put(b"\x01\x03")
    await asyncio.sleep(0.05)
    pdu_good = b"\x01\x03\x00\x00\x00\x01"
    crc_good = calculate_crc16(pdu_good)
    await mock_serial_inst.read_queue.put(pdu_good[2:] + crc_good)
    await asyncio.sleep(0.05)
    assert len(mock_serial_inst.write_calls) == 1
    mock_serial_inst.write_calls.clear()

    # Sub-function PDU missing sub-function code (buffer length < 3)
    # Send fc=43 (0x2b)
    await mock_serial_inst.read_queue.put(b"\x01\x2b")
    await asyncio.sleep(0.05)

    # Sub-function PDU code resolution (get_subfunction_pdu_class raising ValueError on sub-function code 0)
    pdu_bad_sub = b"\x01\x2b\x00\x00\x00"
    await mock_serial_inst.read_queue.put(pdu_bad_sub + calculate_crc16(pdu_bad_sub))
    await asyncio.sleep(0.05)

    # Valid sub-function code (fc=43, sub=14)
    # Encapsulated Interface Transport (0x2B), mei_type=14 (0x0E), read_device_id=1, object_id=0
    pdu_good_sub = b"\x01\x2b\x0e\x01\x00"
    await mock_serial_inst.read_queue.put(pdu_good_sub + calculate_crc16(pdu_good_sub))
    await asyncio.sleep(0.05)

    # Invalid PDU parameters: quantity = 0 (raises InvalidRequestError in decode_request)
    pdu_invalid_param = b"\x01\x03\x00\x00\x00\x00"
    await mock_serial_inst.read_queue.put(pdu_invalid_param + calculate_crc16(pdu_invalid_param))
    await asyncio.sleep(0.05)

    # Exceed expected total size > MAX_RTU_FRAME_SIZE (raises ValueError, clears buffer silently)
    # byte_count = 250 (so data size 255, total frame 259 > 256)
    pdu_large = b"\x01\x10\x00\x00\x00\x00\xfa"
    await mock_serial_inst.read_queue.put(pdu_large + calculate_crc16(pdu_large))
    await asyncio.sleep(0.05)

    # Verify write calls: only invalid param writes exception response, others clear buffer silently
    assert len(mock_serial_inst.write_calls) == 1
    mock_serial_inst.write_calls.clear()

    # 1. Serial port read exception in loop (run while loop is still active!)
    with patch.object(mock_serial_inst, "read", side_effect=RuntimeError("Serial Read Failure")):
        await mock_serial_inst.read_queue.put(b"\x00")
        await asyncio.sleep(0.15)

    # 2. Fragmented Write Multiple Coils request (FC 15) to hit coils.py lines 388-391
    await mock_serial_inst.read_queue.put(b"\x01\x0f\x00\x00\x00")
    await asyncio.sleep(0.05)
    pdu_coils = b"\x01\x0f\x00\x00\x00\x08\x01\xff"
    await mock_serial_inst.read_queue.put(pdu_coils[5:] + calculate_crc16(pdu_coils))
    await asyncio.sleep(0.05)
    assert len(mock_serial_inst.write_calls) == 1
    mock_serial_inst.write_calls.clear()

    # 3. Fragmented Write Multiple Registers request (FC 16) to hit holding_registers.py line 567
    # Note: the handler for WriteMultipleRegistersPDU unsets server._serial and terminates the loop.
    await mock_serial_inst.read_queue.put(b"\x01\x10\x00\x00\x00")
    await asyncio.sleep(0.05)
    pdu_regs = b"\x01\x10\x00\x00\x00\x01\x02\x00\x01"
    await mock_serial_inst.read_queue.put(pdu_regs[5:] + calculate_crc16(pdu_regs))
    await asyncio.sleep(0.15)
    # The handler set server._serial to None. No response write call should have occurred.
    assert len(mock_serial_inst.write_calls) == 0

    await server.stop()


async def test_rtu_server_read_exception_empty_buffer() -> None:
    """Test RTU server exception handling when buffer is empty."""
    router = ModbusRequestRouter()
    server = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    with patch.object(MockSerial, "read", side_effect=RuntimeError("Serial Read Failure")):
        await server.start()
        await asyncio.sleep(0.15)
        await server.stop()


async def test_rtu_server_unregistered_unit_id_ignored() -> None:
    """Test that RTU server silently ignores requests with unregistered unit IDs."""
    router = ModbusRequestRouter()

    # Register only for unit_id=1
    @router.register(ReadHoldingRegistersPDU, unit_id=1)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [0x7777]

    server = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = cast("MockSerial", server._reader)
    assert mock_serial_inst is not None

    # Feed a frame targeting unit_id=2 (unregistered)
    pdu = b"\x02\x03\x00\x00\x00\x01"
    crc = calculate_crc16(pdu)
    with patch("tmodbus.server.async_rtu.log_raw_traffic") as mock_log:
        for b in pdu + crc:
            await mock_serial_inst.read_queue.put(bytes([b]))

        await asyncio.sleep(0.05)

        # Should NOT have sent any response
        assert len(mock_serial_inst.write_calls) == 0

        # Verify it was logged as ignored
        mock_log.assert_any_call("recv", pdu + crc, is_error=False, is_ignored=True)

    await server.stop()


async def test_rtu_server_broadcast() -> None:
    """Test that RTU server processes broadcast (unit_id=0) but sends no response."""
    router = ModbusRequestRouter()
    called = False

    @router.register(ReadHoldingRegistersPDU, unit_id=0)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        nonlocal called
        called = True
        return [0x7777]

    server = AsyncRtuServer(port="/dev/ttyUSB0", handler=router)
    await server.start()

    mock_serial_inst = cast("MockSerial", server._reader)
    assert mock_serial_inst is not None

    # Feed a frame targeting unit_id=0 (broadcast)
    pdu = b"\x00\x03\x00\x00\x00\x01"
    crc = calculate_crc16(pdu)
    for b in pdu + crc:
        await mock_serial_inst.read_queue.put(bytes([b]))

    await asyncio.sleep(0.05)

    # Should have called the handler
    assert called is True
    # Should NOT have sent any response
    assert len(mock_serial_inst.write_calls) == 0

    await server.stop()
