"""Tests for server handler and router implementation."""

import pytest
from tmodbus.exceptions import IllegalDataAddressError, IllegalFunctionError
from tmodbus.pdu import ReadHoldingRegistersPDU, WriteSingleRegisterPDU
from tmodbus.server import ModbusRequestRouter, handle_modbus_request


async def test_router_registration_and_dispatch() -> None:
    """Test registering handlers on ModbusRequestRouter and calling it."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
        assert unit_id == 1
        assert request.start_address == 10
        assert request.quantity == 5
        return [42] * request.quantity

    # Test routing a registered request
    req = ReadHoldingRegistersPDU(start_address=10, quantity=5)
    resp = await router(1, req)
    assert resp == [42, 42, 42, 42, 42]

    # Test routing an unregistered request
    unregistered_req = WriteSingleRegisterPDU(address=10, value=100)
    with pytest.raises(IllegalFunctionError):
        await router(1, unregistered_req)


async def test_handle_modbus_request_success() -> None:
    """Test handle_modbus_request encodes successful responses."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [1, 2]

    req = ReadHoldingRegistersPDU(start_address=0, quantity=2)
    response_bytes = await handle_modbus_request(1, req, router)
    # ReadHoldingRegistersPDU response: function_code (1 byte) + byte_count (1 byte) + data (4 bytes)
    assert response_bytes == b"\x03\x04\x00\x01\x00\x02"


async def test_handle_modbus_request_modbus_error() -> None:
    """Test handle_modbus_request maps ModbusResponseError to exception responses."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
        raise IllegalDataAddressError(2, request.function_code)

    req = ReadHoldingRegistersPDU(start_address=0, quantity=2)
    response_bytes = await handle_modbus_request(1, req, router)
    # Expected exception response: (function_code | 0x80) (1 byte) + error_code (1 byte)
    assert response_bytes == b"\x83\x02"


async def test_handle_modbus_request_unexpected_error() -> None:
    """Test handle_modbus_request maps generic exceptions to ServerDeviceFailure."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        msg = "Something went wrong"
        raise RuntimeError(msg)

    req = ReadHoldingRegistersPDU(start_address=0, quantity=2)
    response_bytes = await handle_modbus_request(1, req, router)
    # Expected SERVER_DEVICE_FAILURE exception code (0x04)
    assert response_bytes == b"\x83\x04"
