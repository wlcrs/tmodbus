"""Integration tests against the Rust Tokio Modbus server."""

import subprocess
import time
from collections.abc import Generator
from pathlib import Path

import pytest
from tmodbus.client import AsyncModbusClient
from tmodbus.transport import AsyncRtuTransport, AsyncTcpTransport
from tmodbus.transport.async_base import AsyncBaseTransport


@pytest.fixture
def log_traffic(caplog: pytest.LogCaptureFixture) -> None:
    """Increase logging level for easy debugging."""
    caplog.set_level("DEBUG", logger="tmodbus")


@pytest.fixture(scope="session")
def server() -> Generator[None]:
    """Start socat and server process."""
    # Use socat to create a virtual serial port
    socat_process = subprocess.Popen(
        [
            "/usr/bin/socat",
            "-d",
            "-d",
            "-v",
            "pty,rawer,echo=0,link=./server-socket",
            "pty,rawer,echo=0,link=./client-socket",
        ],
        cwd=str(Path(__file__).parent),
    )

    time.sleep(0.05)  # allow the socat process to start

    # Start the server process and connect it to the socat server-socket
    server_process = subprocess.Popen(  # noqa: S603
        [
            str(Path(__file__).parent / "target/release/server"),
            str(Path(__file__).with_name("server-socket")),
        ],
    )

    time.sleep(0.05)  # allow the server process to start

    yield
    server_process.kill()
    socat_process.terminate()
    server_process.wait()
    socat_process.wait()


@pytest.mark.parametrize(
    "transport",
    [
        AsyncTcpTransport("127.0.0.1", 5502),
        AsyncRtuTransport(str(Path(__file__).with_name("client-socket")), baudrate=19200),
    ],
    ids=["tcp", "rtu"],
)
@pytest.mark.usefixtures("log_traffic", "server")
async def test_client(transport: AsyncBaseTransport) -> None:
    """Test client against the server."""
    client = AsyncModbusClient(transport=transport, unit_id=1)
    await client.connect()
    # Perform read/write operations using the client

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

    await client.disconnect()


if __name__ == "__main__":
    pytest.main(
        [
            str(Path(__file__).parent),
        ]
    )
