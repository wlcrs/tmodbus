"""Modbus Server Handler Protocol."""

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from tmodbus.const import ExceptionCode
from tmodbus.exceptions import ModbusResponseError
from tmodbus.pdu import BasePDU

logger = logging.getLogger(__name__)

# A ModbusHandler is a function that takes a unit_id and a PDU request, and returns the response payload
# or raises a ModbusResponseError.
type ModbusHandler = Callable[[int, BasePDU[Any]], Awaitable[Any]]


class ModbusRequestRouter:
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

    async def __call__(self, unit_id: int, request: BasePDU[Any]) -> Any:
        handler = self._handlers.get(request.function_code)
        if handler is None:
            from tmodbus.const import ExceptionCode
            from tmodbus.exceptions import IllegalFunctionError
            raise IllegalFunctionError(ExceptionCode.ILLEGAL_FUNCTION, request.function_code)
        return await handler(unit_id, request)


async def handle_modbus_request[T](
    unit_id: int,
    request: BasePDU[T],
    handler: Callable[[int, BasePDU[T]], Awaitable[T]],
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
