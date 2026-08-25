"""Integration tests against the Rust rmodbus server."""

import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path

import pytest
from tmodbus.client import AsyncModbusClient
from tmodbus.transport import AsyncRtuTransport, AsyncTcpTransport
from tmodbus.transport.async_ascii import AsyncAsciiTransport
from tmodbus.transport.async_base import AsyncBaseTransport

sys.path.append(str(Path(__file__).parent.parent))
from helpers import make_virtual_serial_ports


@pytest.fixture
def log_traffic(caplog: pytest.LogCaptureFixture) -> None:
    """Increase logging level for easy debugging."""
    caplog.set_level("DEBUG", logger="tmodbus")


@pytest.fixture(scope="session")
def server() -> Generator[None]:
    """Start socat and server process."""
    server_path = Path(__file__).parent / "server-socket"
    client_path = Path(__file__).parent / "client-socket"
    with make_virtual_serial_ports(server_path, client_path):
        # Start the server process and connect it to the socat server-socket
        server_process = subprocess.Popen(  # noqa: S603
            [
                str(Path(__file__).parent / "target/release/server"),
                str(server_path),
            ],
        )

        time.sleep(0.05)  # allow the server process to start

        yield
        server_process.kill()
        server_process.wait()


@pytest.fixture(scope="session")
def ascii_server() -> Generator[None]:
    """Start socat and server process."""
    server_path = Path(__file__).parent / "ascii-server-socket"
    client_path = Path(__file__).parent / "ascii-client-socket"
    with make_virtual_serial_ports(server_path, client_path):
        # Start the server process and connect it to the socat server-socket
        server_process = subprocess.Popen(  # noqa: S603
            [
                str(Path(__file__).parent / "target/release/ascii-server"),
                str(server_path),
            ],
        )

        time.sleep(0.05)  # allow the server process to start

        yield
        server_process.kill()
        server_process.wait()


@pytest.mark.parametrize(
    "transport",
    [
        AsyncTcpTransport("127.0.0.1", 5502),
        AsyncRtuTransport(str(Path(__file__).with_name("client-socket")), baudrate=19200),
        AsyncAsciiTransport(str(Path(__file__).with_name("ascii-client-socket")), baudrate=19200),
    ],
    ids=[
        "tcp",
        "rtu",
        "ascii",
    ],
)
@pytest.mark.usefixtures("log_traffic", "server", "ascii_server")
async def test_client(transport: AsyncBaseTransport) -> None:
    """Test client against the server."""
    client = AsyncModbusClient(transport=transport, unit_id=1)
    await client.connect()
    # Perform read/write operations using the client

    # Coils
    await client.write_single_coil(0, value=True)
    assert await client.read_coils(0, 1) == [True]
    await client.write_multiple_coils(5, [True, False, True, True])

    assert await client.read_coils(5, 4) == [True, False, True, True]

    # First write to some registers
    await client.write_multiple_registers(0, [10, 20, 30, 40])

    # now read the contents of the registers back
    hr0_4 = await client.read_holding_registers(0, 4)
    assert hr0_4 == [10, 20, 30, 40]

    # Write a single register
    await client.write_single_register(0, 50)
    hr0_4 = await client.read_holding_registers(0, 4)
    assert hr0_4 == [50, 20, 30, 40]

    # Read the input registers
    ir0_1 = await client.read_input_registers(0, 2)
    assert ir0_1 == [1234, 5678]

    # Struct / Typed helpers
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

    await client.write_string(62, "HelloRModbus", number_of_registers=6)
    assert (await client.read_string(62, number_of_registers=6)).rstrip("\x00") == "HelloRModbus"

    await client.disconnect()


if __name__ == "__main__":
    pytest.main(
        [
            str(Path(__file__).parent),
        ]
    )
