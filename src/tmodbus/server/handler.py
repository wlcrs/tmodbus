"""Modbus Server Handler Protocol."""

import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeGuard

from tmodbus.const import ExceptionCode
from tmodbus.exceptions import ModbusResponseError
from tmodbus.pdu import BaseClientPDU, BasePDU

logger = logging.getLogger(__name__)


def is_server_pdu_class(pdu_class: type[BaseClientPDU[Any]]) -> TypeGuard[type[BasePDU[Any]]]:
    """Type guard to check if a PDU class implements server-side methods."""
    return issubclass(pdu_class, BasePDU)

# A ModbusHandler is a protocol representing a callable that processes a request PDU
# and returns the response payload of the matching type.
class ModbusHandler(Protocol):
    """Protocol for Modbus request handlers."""

    def __call__[T](self, unit_id: int, request: BasePDU[T], /) -> Awaitable[T]:
        """Process a Modbus request and return the response value."""
        ...


class ModbusRequestRouter(ModbusHandler):
    """A type-safe dispatcher/router for Modbus requests."""

    def __init__(self) -> None:
        self._handlers: dict[int, Callable[[int, Any], Awaitable[Any]]] = {}

    def register[T](
        self, pdu_class: type[BasePDU[T]]
    ) -> Callable[[Callable[[int, BasePDU[T]], Awaitable[T]]], Callable[[int, BasePDU[T]], Awaitable[T]]]:
        """Register a handler for a specific request PDU class with complete static type safety."""
        def decorator(handler: Callable[[int, BasePDU[T]], Awaitable[T]]) -> Callable[[int, BasePDU[T]], Awaitable[T]]:
            self._handlers[pdu_class.function_code] = handler
            return handler
        return decorator

    async def __call__[T](self, unit_id: int, request: BasePDU[T]) -> T:
        handler = self._handlers.get(request.function_code)
        if handler is None:
            from tmodbus.const import ExceptionCode
            from tmodbus.exceptions import IllegalFunctionError
            raise IllegalFunctionError(ExceptionCode.ILLEGAL_FUNCTION, request.function_code)
        return await handler(unit_id, request)


async def handle_modbus_request[T](
    unit_id: int,
    request: BasePDU[T],
    handler: ModbusHandler,
) -> bytes:
    """Handle a Modbus request using the given handler and encode the response.

    Args:
        unit_id: The slave address / unit id
        request: The parsed request PDU
        handler: The user-defined handler function

    Returns:
        The encoded response PDU (either normal or exception)

    """
    try:
        response_data = await handler(unit_id, request)
        return request.encode_response(response_data)
    except ModbusResponseError as e:
        logger.warning(
            "Modbus Exception %s (%s) for unit_id %d, function %s",
            e.error_code,
            e.__class__.__name__,
            unit_id,
            request.function_code,
        )
        return bytes([request.function_code | 0x80, e.error_code])
    except Exception:
        logger.exception("Unexpected error in Modbus handler for unit_id %d", unit_id)
        # For completely unexpected errors, we default to returning ServerDeviceFailure
        return bytes([request.function_code | 0x80, ExceptionCode.SERVER_DEVICE_FAILURE])
