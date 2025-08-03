from typing import TypeVar

import pytest

from tmodbus.client.async_client import AsyncModbusClient
from tmodbus.pdu import BaseModbusPDU, ReadCoilsPDU
from tmodbus.transport.async_base import AsyncBaseTransport

RT = TypeVar("RT")

DUMMY_RESPONSE = "dummy_response"


class DummyAsyncTransport(AsyncBaseTransport):
    """A dummy async transport for testing purposes."""

    def __init__(self) -> None:
        """Initialize the dummy transport."""
        self.performed_actions = []
        self.opened = False

    async def open(self) -> None:
        """Open the transport connection."""
        self.performed_actions.append("open")
        self.opened = True

    async def close(self) -> None:
        """Close the transport connection."""
        self.performed_actions.append("close")
        self.opened = False

    def is_open(self) -> bool:
        """Check if the transport connection is open."""
        self.performed_actions.append("is_open")
        return self.opened

    async def send_and_receive(self, unit_id: int, pdu: BaseModbusPDU[RT]) -> RT:
        """Send a PDU and receive a response."""
        self.performed_actions.append(["send_and_receive", unit_id, type(pdu).__name__])
        # For testing, just return a fixed dummy response
        return DUMMY_RESPONSE  # type: ignore[report-return-type]


@pytest.fixture
def dummy_client() -> AsyncModbusClient:
    """Create a dummy async Modbus client."""
    transport = DummyAsyncTransport()
    return AsyncModbusClient(transport)


async def test_async_modbus_client_open_close(dummy_client: AsyncModbusClient):
    """Test opening and closing the transport connection."""
    # Initially, the transport should not be open
    assert not dummy_client.transport.is_open()

    # Open the transport connection
    await dummy_client.transport.open()
    assert dummy_client.transport.is_open()
    assert "open" in dummy_client.transport.performed_actions

    # Close the transport connection
    await dummy_client.transport.close()
    assert not dummy_client.transport.is_open()
    assert "close" in dummy_client.transport.performed_actions


def test_async_modbus_client_initialization():
    """Test initialization of AsyncModbusClient with DummyAsyncTransport."""
    transport = DummyAsyncTransport()
    client = AsyncModbusClient(transport)
    assert client.transport == transport
    assert isinstance(client.transport, AsyncBaseTransport)


async def test_async_modbus_client_execute(dummy_client: AsyncModbusClient):
    """Test the execute method of AsyncModbusClient."""
    unit_id = 1
    pdu = ReadCoilsPDU(start_address=0, quantity=8)

    # Execute the PDU request
    response = await dummy_client.execute(pdu, unit_id=unit_id)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadCoilsPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_read_coils(dummy_client: AsyncModbusClient):
    """Test the read_coils method of AsyncModbusClient."""
    unit_id = 1
    start_address = 0
    quantity = 8

    # Execute the read_coils request
    response = await dummy_client.read_coils(start_address, quantity, unit_id=unit_id)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadCoilsPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_read_discrete_inputs(dummy_client: AsyncModbusClient):
    """Test the read_discrete_inputs method of AsyncModbusClient."""
    unit_id = 1
    start_address = 0
    quantity = 8

    # Execute the read_discrete_inputs request
    response = await dummy_client.read_discrete_inputs(start_address, quantity, unit_id=unit_id)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadDiscreteInputsPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_read_holding_registers(dummy_client: AsyncModbusClient):
    """Test the read_holding_registers method of AsyncModbusClient."""
    unit_id = 1
    start_address = 0
    quantity = 8

    # Execute the read_holding_registers request
    response = await dummy_client.read_holding_registers(start_address, quantity, unit_id=unit_id)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadHoldingRegistersPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_read_input_registers(dummy_client: AsyncModbusClient):
    """Test the read_input_registers method of AsyncModbusClient."""
    unit_id = 1
    start_address = 0
    quantity = 8

    # Execute the read_input_registers request
    response = await dummy_client.read_input_registers(start_address, quantity, unit_id=unit_id)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadInputRegistersPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_write_single_coil(dummy_client: AsyncModbusClient):
    """Test the write_single_coil method of AsyncModbusClient."""
    unit_id = 1
    address = 0
    value = True

    # Execute the write_single_coil request
    response = await dummy_client.write_single_coil(address, value, unit_id=unit_id)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "WriteSingleCoilPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_write_multiple_coils(dummy_client: AsyncModbusClient):
    """Test the write_multiple_coils method of AsyncModbusClient."""
    unit_id = 1
    start_address = 0
    values = [True, False, True, False]

    # Execute the write_multiple_coils request
    response = await dummy_client.write_multiple_coils(start_address, values, unit_id=unit_id)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "WriteMultipleCoilsPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_write_single_register(dummy_client: AsyncModbusClient):
    """Test the write_single_register method of AsyncModbusClient."""
    unit_id = 1
    address = 0
    value = 1234

    # Execute the write_single_register request
    response = await dummy_client.write_single_register(address, value, unit_id=unit_id)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "WriteSingleRegisterPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_write_multiple_registers(dummy_client: AsyncModbusClient):
    """Test the write_multiple_registers method of AsyncModbusClient."""
    unit_id = 1
    start_address = 0
    values = [1234, 5678, 123]

    # Execute the write_multiple_registers request
    response = await dummy_client.write_multiple_registers(start_address, values, unit_id=unit_id)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "WriteMultipleRegistersPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_context_manager(dummy_client: AsyncModbusClient):
    """Test the async context manager functionality of AsyncModbusClient."""
    assert not dummy_client.transport.is_open()

    async with dummy_client as client:
        assert client.transport.is_open()
        assert "open" in client.transport.performed_actions

    assert not client.transport.is_open()
    assert "close" in client.transport.performed_actions
