"""Integration tests against the FieldTalk diagslave simulator."""

import asyncio
import contextlib
import logging
import sys
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from tmodbus.client import AsyncModbusClient
from tmodbus.transport import (
    AsyncAsciiTransport,
    AsyncRtuOverTcpTransport,
    AsyncRtuTransport,
    AsyncTcpTransport,
    AsyncUdpTransport,
)

sys.path.append(str(Path(__file__).parent.parent))
from helpers import find_free_port, make_virtual_serial_ports

DIAGSLAVE_BIN = Path(__file__).parent / "diagslave"

logger = logging.getLogger(__name__)


@pytest.fixture
def log_traffic(caplog: pytest.LogCaptureFixture) -> None:
    """Increase logging level for easy debugging."""
    caplog.set_level("DEBUG", logger="tmodbus")


@contextlib.asynccontextmanager
async def diagslave(protocol_mode: str, *args: str) -> AsyncGenerator[asyncio.subprocess.Process, None]:
    """Asynchronous context manager to manage the lifecycle of a diagslave server process."""
    process = await asyncio.create_subprocess_exec(
        str(DIAGSLAVE_BIN),
        "-m",
        protocol_mode,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    # Wait for the simulator to fully initialize
    await asyncio.sleep(0.5)
    try:
        yield process
    finally:
        if process.returncode is None:
            process.terminate()
        stdout, stderr = await process.communicate()
        if stdout:
            logger.debug("diagslave stdout:\n%s", stdout.decode())
        if stderr:
            logger.debug("diagslave stderr:\n%s", stderr.decode())


async def run_client_assertions(client: AsyncModbusClient) -> None:
    """Run all assertions against the diagslave client."""
    # 1. Coils
    # Write single coil and read back
    await client.write_single_coil(0, value=True)

    res = await client.read_coils(0, 1)
    assert res == [True]

    # Write multiple coils and read back
    await client.write_multiple_coils(5, [True, False, True, True])

    res = await client.read_coils(5, 4)
    assert res == [True, False, True, True]

    # 2. Discrete Inputs
    # diagslave maps discrete inputs directly to coils memory.
    # Verify we can read the discrete inputs written above.
    res = await client.read_discrete_inputs(0, 1)
    assert res == [True]

    res = await client.read_discrete_inputs(5, 4)
    assert res == [True, False, True, True]

    # 3. Holding Registers
    # Write single register and read back
    await client.write_single_register(10, 42)

    res = await client.read_holding_registers(10, 1)
    assert res == [42]

    # Write multiple registers and read back
    await client.write_multiple_registers(20, [100, 200, 300])

    res = await client.read_holding_registers(20, 3)
    assert res == [100, 200, 300]

    # Mask Write Register (FC22)
    # Write 0x1234, mask it (AND 0x00FF, OR 0x5600), expect 0x5634
    await client.write_single_register(30, 0x1234)

    await client.mask_write_register(30, and_mask=0x00FF, or_mask=0x5600)

    res = await client.read_holding_registers(30, 1)
    assert res == [0x5634]

    # Read/Write Multiple Registers (FC23)
    # Read from address 40 (qty 2) and write values [88, 99] to address 40 in one transaction
    res = await client.read_write_multiple_registers(
        read_start_address=40,
        read_quantity=2,
        write_start_address=40,
        write_values=[88, 99],
    )
    assert res == [88, 99]

    # 4. Input Registers
    # diagslave maps input registers directly to holding registers memory.
    # Verify we can read holding registers as input registers.
    res = await client.read_input_registers(10, 1)
    assert res == [42]

    res = await client.read_input_registers(20, 3)
    assert res == [100, 200, 300]


@pytest.mark.usefixtures("log_traffic")
async def test_diagslave_tcp() -> None:
    """Test tmodbus client using Modbus/TCP against diagslave."""
    port = find_free_port()
    async with diagslave("tcp", "-p", str(port)):
        transport = AsyncTcpTransport("127.0.0.1", port)
        client = AsyncModbusClient(transport=transport, unit_id=1)
        await client.connect()
        await run_client_assertions(client)
        await client.disconnect()


@pytest.mark.usefixtures("log_traffic")
async def test_diagslave_udp() -> None:
    """Test tmodbus client using Modbus UDP against diagslave."""
    port = find_free_port()
    async with diagslave("udp", "-p", str(port)):
        transport = AsyncUdpTransport("127.0.0.1", port)
        client = AsyncModbusClient(transport=transport, unit_id=1)
        await client.connect()
        await run_client_assertions(client)
        await client.disconnect()


@pytest.mark.usefixtures("log_traffic")
async def test_diagslave_rtu_over_tcp() -> None:
    """Test tmodbus client using Modbus RTU over TCP against diagslave."""
    port = find_free_port()
    async with diagslave("enc", "-p", str(port)):
        transport = AsyncRtuOverTcpTransport("127.0.0.1", port)
        client = AsyncModbusClient(transport=transport, unit_id=1)
        await client.connect()
        await run_client_assertions(client)
        await client.disconnect()


@pytest.mark.usefixtures("log_traffic")
async def test_diagslave_rtu_serial() -> None:
    """Test tmodbus client using Modbus RTU (serial) against diagslave."""
    server_path = Path(__file__).parent / "rtu-server-socket"
    client_path = Path(__file__).parent / "rtu-client-socket"

    with make_virtual_serial_ports(server_path, client_path):
        async with diagslave("rtu", "-o", "10", str(server_path)):
            transport = AsyncRtuTransport(
                str(client_path),
                baudrate=19200,
                timeout=3.0,
            )
            client = AsyncModbusClient(transport=transport, unit_id=1)
            await client.connect()
            await run_client_assertions(client)
            await client.disconnect()


@pytest.mark.usefixtures("log_traffic")
async def test_diagslave_ascii_serial() -> None:
    """Test tmodbus client using Modbus ASCII (serial) against diagslave."""
    server_path = Path(__file__).parent / "ascii-server-socket"
    client_path = Path(__file__).parent / "ascii-client-socket"

    with make_virtual_serial_ports(server_path, client_path):
        async with diagslave("ascii", "-o", "10", str(server_path)):
            transport = AsyncAsciiTransport(
                str(client_path),
                baudrate=19200,
                timeout=3.0,
            )
            client = AsyncModbusClient(transport=transport, unit_id=1)
            await client.connect()
            await run_client_assertions(client)
            await client.disconnect()
