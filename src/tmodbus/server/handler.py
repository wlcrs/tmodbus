"""Modbus Server Handler Protocol."""

import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeGuard

from tmodbus.const import ExceptionCode
from tmodbus.exceptions import IllegalFunctionError, ModbusResponseError
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
        """Initialize the ModbusRequestRouter.

        This router acts as a centralized dispatcher for incoming Modbus request PDUs.
        It maps Modbus function codes to async handler functions with full static type
        safety.

        Examples:
            Creating and using a router for a Modbus server:

            ```python
            from tmodbus.pdu import ReadHoldingRegistersRequest
            from tmodbus.server import AsyncTcpServer, ModbusRequestRouter

            router = ModbusRequestRouter()


            # Register handler for specific Modbus requests
            @router.register(ReadHoldingRegistersRequest)
            async def handle_read_holding_registers(
                unit_id: int, request: ReadHoldingRegistersRequest
            ) -> list[int]:
                # Implement holding registers reading logic
                # Must return a list of integers corresponding to registers
                return [42] * request.quantity


            # Pass the router as the handler to the Modbus server
            server = AsyncTcpServer(host="localhost", port=502, handler=router)
            await server.serve_forever()
            ```

        """
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
        """Route the incoming Modbus request to its registered handler.

        Args:
            unit_id: The slave address / unit ID of the target device.
            request: The parsed Modbus request PDU.

        Returns:
            The output payload returned by the registered handler, typed
            specifically to the request PDU.

        Raises:
            IllegalFunctionError: If no handler is registered for the function code
                specified in the request PDU.

        """
        handler = self._handlers.get(request.function_code)
        if handler is None:
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
