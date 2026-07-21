"""Tests for server handler and router implementation."""

from collections.abc import Awaitable
from typing import Any, cast

import pytest
from tmodbus.exceptions import IllegalDataAddressError, IllegalFunctionError
from tmodbus.pdu import BasePDU, ReadHoldingRegistersPDU, WriteSingleRegisterPDU
from tmodbus.server import (
    AnyModbusHandler,
    ModbusHandler,
    ModbusRequestRouter,
    RequestContext,
)
from tmodbus.server.handler import (
    ContextAwareModbusHandler,
    handle_modbus_request,
    handler_supports_unit_id,
)


async def test_default_supports_unit_id() -> None:
    """Test the default supports_unit_id function."""

    class MyHandler(ModbusHandler):
        def __call__(self, unit_id: int, request: BasePDU[Any]) -> Awaitable[Any]:
            raise NotImplementedError

    class MyContextHandler(ContextAwareModbusHandler):
        def __call__(self, unit_id: int, request: BasePDU[Any], context: RequestContext) -> Awaitable[Any]:
            raise NotImplementedError

    assert MyHandler().supports_unit_id(1) is True
    assert MyContextHandler().supports_unit_id(1) is True


async def test_router_registration_and_dispatch() -> None:
    """Test registering handlers on ModbusRequestRouter and calling it."""
    router = ModbusRequestRouter()

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
        assert unit_id == 1
        assert request.start_address == 10
        assert request.quantity == 5
        return [42] * request.quantity

    with pytest.raises(ValueError, match="already registered"):
        # we don't support registering multiple handlers for the same function code/unit id as this
        # is a footgun.

        @router.register(ReadHoldingRegistersPDU)
        async def handle_read_duplicate(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
            return [-1]

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
        raise IllegalDataAddressError(request.function_code)

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


async def test_router_unit_id_routing() -> None:
    """Test routing with specific unit IDs, fallback behavior, and multiple unit ID registration."""
    router = ModbusRequestRouter()

    # Register for specific unit ID 1
    @router.register(ReadHoldingRegistersPDU, unit_id=1)
    async def handle_unit_1(_unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
        return [1] * request.quantity

    # Register for multiple unit IDs: 2 and 3
    @router.register(ReadHoldingRegistersPDU, unit_id=[2, 3])
    async def handle_units_2_3(unit_id: int, request: ReadHoldingRegistersPDU) -> list[int]:
        return [unit_id] * request.quantity

    # Test routing before a wildcard handler for ReadHoldingRegistersPDU is registered
    with pytest.raises(IllegalFunctionError):
        await router(4, ReadHoldingRegistersPDU(start_address=10, quantity=3))

    # Register a general default handler for WriteSingleRegisterPDU (no unit_id specified)
    @router.register(WriteSingleRegisterPDU)
    async def handle_write_default(_unit_id: int, _request: WriteSingleRegisterPDU) -> int:
        return 99

    # Register a specific handler for WriteSingleRegisterPDU on unit_id=5
    @router.register(WriteSingleRegisterPDU, unit_id=5)
    async def handle_write_unit_5(_unit_id: int, _request: WriteSingleRegisterPDU) -> int:
        return 55

    # Test routing to unit_id=1
    req_read = ReadHoldingRegistersPDU(start_address=10, quantity=3)
    resp = await router(1, req_read)
    assert resp == [1, 1, 1]

    # Test routing to unit_id=2 and 3
    assert await router(2, req_read) == [2, 2, 2]
    assert await router(3, req_read) == [3, 3, 3]

    # Test routing to an unregistered unit_id (e.g. 4) for ReadHoldingRegistersPDU
    with pytest.raises(IllegalFunctionError):
        await router(4, req_read)

    # Test WriteSingleRegisterPDU routing
    req_write = WriteSingleRegisterPDU(address=10, value=100)
    # Unit 5 should route to specific handler
    assert await router(5, req_write) == 55
    # Unit 6 should route to default handler
    assert await router(6, req_write) == 99

    # Test supports_unit_id helper
    assert router.supports_unit_id(1) is True
    assert router.supports_unit_id(2) is True
    assert router.supports_unit_id(3) is True
    assert router.supports_unit_id(5) is True
    assert router.supports_unit_id(6) is True  # True because of the default (None) handler
    assert router.supports_unit_id(4) is True  # True because WriteSingleRegisterPDU has a default (None) handler
    assert router.supports_unit_id(0) is True

    # Test supports_unit_id with strict registration (no default handlers)
    strict_router = ModbusRequestRouter()

    @strict_router.register(ReadHoldingRegistersPDU, unit_id=[1, 2])
    async def handle_strict(_unit_id: int, _request: ReadHoldingRegistersPDU) -> list[int]:
        return [42]

    assert strict_router.supports_unit_id(1) is True
    assert strict_router.supports_unit_id(2) is True
    assert strict_router.supports_unit_id(3) is False
    assert strict_router.supports_unit_id(0) is False


async def test_router_context_passing() -> None:
    """Test that RequestContext is successfully passed to context-aware handlers."""
    router = ModbusRequestRouter()
    captured: list[RequestContext | None] = []

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU, context: RequestContext) -> list[int]:
        captured.append(context)
        return [42]

    ctx = RequestContext(peer_addr=("127.0.0.1", 12345))
    req = ReadHoldingRegistersPDU(start_address=0, quantity=1)
    await router(1, req, context=ctx)

    assert len(captured) == 1
    assert captured[0] is ctx
    assert captured[0].peer_addr == ("127.0.0.1", 12345)


async def test_handle_modbus_request_plain_handler() -> None:
    """Test handle_modbus_request with a plain handler that does not accept context."""

    async def plain_handler(unit_id: int, request: BasePDU[Any]) -> list[int]:
        _ = unit_id, request
        return [99]

    req = ReadHoldingRegistersPDU(start_address=0, quantity=1)
    response_bytes = await handle_modbus_request(1, req, cast("AnyModbusHandler", plain_handler))
    assert response_bytes == b"\x03\x02\x00\x63"


async def test_router_ctx_parameter_name_passing() -> None:
    """Test that RequestContext is successfully passed to a handler naming the parameter 'ctx'."""
    router = ModbusRequestRouter()
    captured: list[RequestContext | None] = []

    @router.register(ReadHoldingRegistersPDU)
    async def handle_read(_unit_id: int, _request: ReadHoldingRegistersPDU, ctx: RequestContext) -> list[int]:
        captured.append(ctx)
        return [42]

    ctx = RequestContext(peer_addr=("127.0.0.1", 12345))
    req = ReadHoldingRegistersPDU(start_address=0, quantity=1)
    await router(1, req, context=ctx)

    assert len(captured) == 1
    assert captured[0] is ctx
    assert captured[0].peer_addr == ("127.0.0.1", 12345)


def test_handler_supports_unit_id_plain() -> None:
    """Test handler_supports_unit_id with a plain function/callable."""

    async def plain_func(unit_id: int, request: BasePDU[Any]) -> list[int]:
        _ = unit_id, request
        return []

    assert handler_supports_unit_id(cast("AnyModbusHandler", plain_func), 1) is True
