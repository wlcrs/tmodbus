"""Integration tests for tmodbus against the simonvetter/modbus client and server."""

import asyncio
import sys
from pathlib import Path

import pytest
from tmodbus.client import AsyncModbusClient
from tmodbus.transport import AsyncTcpTransport

sys.path.append(str(Path(__file__).parent.parent))
from helpers import find_free_port

server_bin_path = Path(__file__).parent / "server"


@pytest.mark.asyncio
async def test_tcp_client() -> None:
    """Test tmodbus TCP client against Go server."""
    port = find_free_port()

    # Start Go server
    server_process = await asyncio.create_subprocess_exec(
        str(server_bin_path),
        f"tcp://127.0.0.1:{port}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # Wait for the Go server to bind
    await asyncio.sleep(0.5)

    try:
        client = AsyncModbusClient(transport=AsyncTcpTransport("127.0.0.1", port), unit_id=1)
        await client.connect()

        # 1. Coils
        await client.write_single_coil(0, value=True)
        res = await client.read_coils(0, 1)
        assert res == [True]

        await client.write_multiple_coils(5, [True, False, True, True])
        res = await client.read_coils(5, 4)
        assert res == [True, False, True, True]

        # 2. Discrete Inputs
        res = await client.read_discrete_inputs(0, 4)
        assert res == [True, False, True, False]

        # 3. Holding Registers
        await client.write_single_register(10, 42)
        res = await client.read_holding_registers(10, 1)
        assert res == [42]

        await client.write_multiple_registers(20, [100, 200, 300])
        res = await client.read_holding_registers(20, 3)
        assert res == [100, 200, 300]

        # 4. Input Registers
        res = await client.read_input_registers(0, 2)
        assert res == [1234, 5678]

        # 5. Struct / Typed helpers
        await client.write_int16(50, -1234)
        assert await client.read_int16(50) == -1234

        await client.write_uint16(51, 65000)
        assert await client.read_uint16(51) == 65000

        await client.write_int32(52, -12345678)
        assert await client.read_int32(52) == -12345678

        await client.write_uint32(54, 3000000000)
        assert await client.read_uint32(54) == 3000000000

        await client.write_float(56, 3.141592)
        assert pytest.approx(await client.read_float(56), rel=1e-5) == 3.141592

        await client.write_double(58, 2.718281828459045)
        assert pytest.approx(await client.read_double(58), rel=1e-9) == 2.718281828459045

        await client.write_string(62, "SimonVetter", number_of_registers=6)
        assert (await client.read_string(62, number_of_registers=6)).rstrip("\x00") == "SimonVetter"

        await client.disconnect()
    finally:
        server_process.terminate()
        await server_process.wait()
