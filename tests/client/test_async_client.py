"""Tests for tmodbus/client/async_client.py ."""

from typing import Any, Literal, TypeVar
from unittest.mock import MagicMock

import pytest
from tmodbus.client.async_client import AsyncModbusClient
from tmodbus.pdu import BasePDU, ReadCoilsPDU, ReadDeviceIdentificationPDU, ReadDeviceIdentificationResponse
from tmodbus.pdu.device import ConformityLevel
from tmodbus.transport.async_base import AsyncBaseTransport

RT = TypeVar("RT")

DUMMY_RESPONSE = "dummy_response"


class DummyAsyncTransport(AsyncBaseTransport):
    """A dummy async transport for testing purposes."""

    def __init__(self) -> None:
        """Initialize the dummy transport."""
        self.performed_actions: list[Any] = []
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

    async def send_and_receive(self, unit_id: int, pdu: BasePDU[RT]) -> RT:  # type: ignore[override]
        """Send a PDU and receive a response."""
        self.performed_actions.append(["send_and_receive", unit_id, type(pdu).__name__])
        # For testing, just return a fixed dummy response
        return DUMMY_RESPONSE  # type: ignore[return-value]


@pytest.fixture
def dummy_client() -> AsyncModbusClient:
    """Create a dummy async Modbus client."""
    transport = DummyAsyncTransport()
    return AsyncModbusClient(transport, unit_id=1)


async def test_async_modbus_client_open_close(dummy_client: AsyncModbusClient) -> None:
    """Test opening and closing the transport connection."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

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


def test_async_modbus_client_initialization() -> None:
    """Test initialization of AsyncModbusClient with DummyAsyncTransport."""
    transport = DummyAsyncTransport()
    client = AsyncModbusClient(transport, unit_id=1)
    assert client.transport == transport
    assert isinstance(client.transport, AsyncBaseTransport)


@pytest.mark.parametrize("unit_id", [-1, 256, 999, -100])
def test_async_modbus_client_unit_id_out_of_bounds(unit_id: int) -> None:
    """Test that AsyncModbusClient raises ValueError for out-of-bounds unit_id."""
    transport = DummyAsyncTransport()
    with pytest.raises(ValueError, match="Unit ID must be in range 0-255"):
        AsyncModbusClient(transport, unit_id=unit_id)


@pytest.mark.parametrize("unit_id", [0, 1, 255])
def test_async_modbus_client_unit_id_in_bounds(unit_id: int) -> None:
    """Test that AsyncModbusClient accepts valid unit_id values."""
    transport = DummyAsyncTransport()
    client = AsyncModbusClient(transport, unit_id=unit_id)
    assert client.unit_id == unit_id
    assert isinstance(client, AsyncModbusClient)


async def test_async_modbus_client_execute(dummy_client: AsyncModbusClient) -> None:
    """Test the execute method of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    unit_id = 1
    pdu = ReadCoilsPDU(start_address=0, quantity=8)

    # Execute the PDU request
    response = await dummy_client.execute(pdu)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadCoilsPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_read_coils(dummy_client: AsyncModbusClient) -> None:
    """Test the read_coils method of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)
    unit_id = 1
    start_address = 0
    quantity = 8

    # Execute the read_coils request
    response = await dummy_client.read_coils(start_address, quantity)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadCoilsPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_read_discrete_inputs(dummy_client: AsyncModbusClient) -> None:
    """Test the read_discrete_inputs method of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    unit_id = 1
    start_address = 0
    quantity = 8

    # Execute the read_discrete_inputs request
    response = await dummy_client.read_discrete_inputs(start_address, quantity)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadDiscreteInputsPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_read_holding_registers(dummy_client: AsyncModbusClient) -> None:
    """Test the read_holding_registers method of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    unit_id = 1
    start_address = 0
    quantity = 8

    # Execute the read_holding_registers request
    response = await dummy_client.read_holding_registers(start_address, quantity)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadHoldingRegistersPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_read_input_registers(dummy_client: AsyncModbusClient) -> None:
    """Test the read_input_registers method of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    unit_id = 1
    start_address = 0
    quantity = 8

    # Execute the read_input_registers request
    response = await dummy_client.read_input_registers(start_address, quantity)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "ReadInputRegistersPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_write_single_coil(dummy_client: AsyncModbusClient) -> None:
    """Test the write_single_coil method of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    unit_id = 1
    address = 0
    value = True

    # Execute the write_single_coil request
    response = await dummy_client.write_single_coil(address, value)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "WriteSingleCoilPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_write_multiple_coils(dummy_client: AsyncModbusClient) -> None:
    """Test the write_multiple_coils method of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    unit_id = 1
    start_address = 0
    values = [True, False, True, False]

    # Execute the write_multiple_coils request
    response = await dummy_client.write_multiple_coils(start_address, values)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "WriteMultipleCoilsPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_write_single_register(dummy_client: AsyncModbusClient) -> None:
    """Test the write_single_register method of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    unit_id = 1
    address = 0
    value = 1234

    # Execute the write_single_register request
    response = await dummy_client.write_single_register(address, value)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "WriteSingleRegisterPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_write_multiple_registers(dummy_client: AsyncModbusClient) -> None:
    """Test the write_multiple_registers method of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    unit_id = 1
    start_address = 0
    values = [1234, 5678, 123]

    # Execute the write_multiple_registers request
    response = await dummy_client.write_multiple_registers(start_address, values)

    # Check if the transport method was called correctly
    assert dummy_client.transport.performed_actions == [["send_and_receive", unit_id, "WriteMultipleRegistersPDU"]]
    assert response == DUMMY_RESPONSE  # The dummy transport returns DUMMY_RESPONSE


async def test_async_modbus_client_context_manager(dummy_client: AsyncModbusClient) -> None:
    """Test the async context manager functionality of AsyncModbusClient."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)
    assert not dummy_client.transport.is_open()

    async with dummy_client as client:
        assert client.transport.is_open()
        assert "open" in dummy_client.transport.performed_actions

    assert not client.transport.is_open()
    assert "close" in dummy_client.transport.performed_actions


async def test_connected_property(dummy_client: MagicMock) -> None:
    """Test the connected property of AsyncModbusClient."""
    # Should reflect transport.is_open()
    dummy_client.transport.opened = True
    assert dummy_client.connected is True
    dummy_client.transport.opened = False
    assert dummy_client.connected is False


async def test_connect_and_close_methods(dummy_client: MagicMock) -> None:
    """Test the connect and close methods of AsyncModbusClient."""
    await dummy_client.connect()
    assert dummy_client.transport.opened is True
    await dummy_client.disconnect()
    assert dummy_client.transport.opened is False


async def test_read_device_identification_single_response(
    monkeypatch: pytest.MonkeyPatch,
    dummy_client: AsyncModbusClient,
) -> None:
    """Test reading device identification with a single response."""
    # Patch execute to return a single response with more=False
    called = {}

    async def fake_execute(_self: None, pdu: ReadDeviceIdentificationPDU) -> ReadDeviceIdentificationResponse:
        called["pdu"] = pdu
        return ReadDeviceIdentificationResponse(
            device_id_code=1,
            conformity_level=ConformityLevel.BASIC,
            objects={1: b"foo"},
            more=False,
            next_object_id=0,
            number_of_objects=1,
        )

    monkeypatch.setattr(AsyncModbusClient, "execute", fake_execute)
    result = await dummy_client.read_device_identification(1, 0)
    assert result == {1: b"foo"}
    assert isinstance(called["pdu"], ReadDeviceIdentificationPDU)


async def test_read_device_identification_multiple_responses(
    monkeypatch: pytest.MonkeyPatch,
    dummy_client: AsyncModbusClient,
) -> None:
    """Test reading device identification with multiple responses."""
    # Patch execute to simulate multiple responses with more=True then more=False
    responses = [
        ReadDeviceIdentificationResponse(
            device_id_code=1,
            conformity_level=ConformityLevel.BASIC,
            objects={1: b"foo"},
            more=True,
            next_object_id=2,
            number_of_objects=2,
        ),
        ReadDeviceIdentificationResponse(
            device_id_code=1,
            conformity_level=ConformityLevel.BASIC,
            objects={2: b"bar"},
            more=False,
            next_object_id=0,
            number_of_objects=2,
        ),
    ]
    call_count = {"count": 0}

    async def fake_execute(_self: None, _pdu: ReadDeviceIdentificationPDU) -> ReadDeviceIdentificationResponse:
        idx = call_count["count"]
        call_count["count"] += 1
        return responses[idx]

    monkeypatch.setattr(AsyncModbusClient, "execute", fake_execute)
    result = await dummy_client.read_device_identification(1, 0)
    assert result == {1: b"foo", 2: b"bar"}
    assert call_count["count"] == 2


async def test_read_device_identification_warns_on_number_of_objects_change(
    monkeypatch: pytest.MonkeyPatch,
    dummy_client: AsyncModbusClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that a warning is logged if number_of_objects changes between requests."""
    # Patch execute to simulate number_of_objects changing between responses
    responses = [
        ReadDeviceIdentificationResponse(
            device_id_code=1,
            conformity_level=ConformityLevel.BASIC,
            objects={1: b"foo"},
            more=True,
            next_object_id=2,
            number_of_objects=2,
        ),
        ReadDeviceIdentificationResponse(
            device_id_code=1,
            conformity_level=ConformityLevel.BASIC,
            objects={2: b"bar"},
            more=False,
            next_object_id=0,
            number_of_objects=3,
        ),
    ]
    call_count = {"count": 0}

    async def fake_execute(_self: None, _pdu: ReadDeviceIdentificationPDU) -> ReadDeviceIdentificationResponse:
        idx = call_count["count"]
        call_count["count"] += 1
        return responses[idx]

    monkeypatch.setattr(AsyncModbusClient, "execute", fake_execute)
    with caplog.at_level("WARNING"):
        await dummy_client.read_device_identification(1, 0)
    assert any("Number of objects changed between requests" in r for r in caplog.text.splitlines())


def test_for_unit_id_creates_new_instance_with_different_unit_id() -> None:
    """Test that for_unit_id creates a new client instance with the specified unit_id."""
    transport = DummyAsyncTransport()
    client1 = AsyncModbusClient(transport, unit_id=1)
    client2 = client1.for_unit_id(42)
    assert isinstance(client2, AsyncModbusClient)
    assert client2.unit_id == 42
    assert client2.transport is client1.transport
    assert client2.word_order == client1.word_order
    assert client2 is not client1


@pytest.mark.parametrize("word_order", ["big", "little"])
def test_for_unit_id_preserves_word_order(word_order: Literal["big", "little"]) -> None:
    """Test that for_unit_id preserves the word_order setting."""
    transport = DummyAsyncTransport()
    client1 = AsyncModbusClient(transport, unit_id=5, word_order=word_order)
    client2 = client1.for_unit_id(10)
    assert client2.word_order == word_order


def test_for_unit_id_raises_value_error_for_invalid_unit_id() -> None:
    """Test that for_unit_id raises ValueError for out-of-bounds unit_id."""
    transport = DummyAsyncTransport()
    client = AsyncModbusClient(transport, unit_id=1)
    with pytest.raises(ValueError, match="Unit ID must be in range 0-255"):
        client.for_unit_id(-1)
    with pytest.raises(ValueError, match="Unit ID must be in range 0-255"):
        client.for_unit_id(256)


async def test_mask_write_register(dummy_client: AsyncModbusClient) -> None:
    """Test mask_write_register method."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    # Test successful mask write
    result = await dummy_client.mask_write_register(0x0004, 0xF2F2, 0x2525)
    assert result == DUMMY_RESPONSE

    # Verify that send_and_receive was called with the correct PDU type
    assert ["send_and_receive", 1, "MaskWriteRegisterPDU"] in dummy_client.transport.performed_actions


async def test_mask_request_server_id(dummy_client: AsyncModbusClient) -> None:
    """Test mask_write_register method."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    # Test successful mask write
    result = await dummy_client.read_server_id()
    assert result == DUMMY_RESPONSE

    # Verify that send_and_receive was called with the correct PDU type
    assert ["send_and_receive", 1, "ReportServerIdPDU"] in dummy_client.transport.performed_actions


async def test_read_write_multiple_registers(dummy_client: AsyncModbusClient) -> None:
    """Test read_write_multiple_registers method."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    # Test successful read/write multiple registers
    read_address = 0x000A
    read_quantity = 4
    write_address = 0x0010
    write_values = [0x1234, 0x5678, 0x9ABC, 0xDEF0]
    result = await dummy_client.read_write_multiple_registers(read_address, read_quantity, write_address, write_values)
    assert result == DUMMY_RESPONSE

    # Verify that send_and_receive was called with the correct PDU type
    assert ["send_and_receive", 1, "ReadWriteMultipleRegistersPDU"] in dummy_client.transport.performed_actions


async def test_read_fifo_queue(dummy_client: AsyncModbusClient) -> None:
    """Test read_fifo_queue method."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    # Test successful read FIFO queue
    fifo_pointer_address = 0x000A
    result = await dummy_client.read_fifo_queue(fifo_pointer_address)
    assert result == DUMMY_RESPONSE

    # Verify that send_and_receive was called with the correct PDU type
    assert ["send_and_receive", 1, "ReadFifoQueuePDU"] in dummy_client.transport.performed_actions


async def test_read_exception_status(dummy_client: AsyncModbusClient) -> None:
    """Test read_exception_status method."""
    assert isinstance(dummy_client.transport, DummyAsyncTransport)

    # Test successful read exception status
    result = await dummy_client.read_exception_status()
    assert result == DUMMY_RESPONSE

    # Verify that send_and_receive was called with the correct PDU type
    assert ["send_and_receive", 1, "ReadExceptionStatusPDU"] in dummy_client.transport.performed_actions
