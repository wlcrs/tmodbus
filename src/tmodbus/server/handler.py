"""Modbus Server Handler Protocol."""

import logging
from collections.abc import Awaitable, Callable, Iterable
from typing import Any, Protocol, TypeGuard, cast

from tmodbus.const import ExceptionCode
from tmodbus.exceptions import IllegalFunctionError, ModbusResponseError
from tmodbus.pdu import BaseClientPDU, BasePDU

logger = logging.getLogger(__name__)


def is_server_pdu_class(pdu_class: type[BaseClientPDU[Any]]) -> TypeGuard[type[BasePDU[Any]]]:
    """Type guard to check if a PDU class implements server-side methods."""
    return issubclass(pdu_class, BasePDU)


# A type alias for the type-erased underlying handler callable.
# We use `Any` because each Modbus function code handles a different PDU class
# and returns a different payload type, and function parameters are contravariant.
type RouterHandler = Callable[[int, Any], Awaitable[Any]]


# A ModbusHandler is a protocol representing a callable that processes a request PDU
# and returns the response payload of the matching type.
class ModbusHandler(Protocol):
    """Protocol for Modbus request handlers."""

    def __call__[T](self, unit_id: int, request: BasePDU[T], /) -> Awaitable[T]:
        """Process a Modbus request and return the response value."""
        ...

    def supports_unit_id(self, _unit_id: int, /) -> bool:
        """Check if the handler supports the given unit ID."""
        return True


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
        # Map of registered handlers.
        #
        # Structure:
        #   Outer Key: `int | None` representing the unit ID (slave address).
        #              `None` acts as a wildcard fallback key for any unit ID.
        #   Inner Key: `int` representing the Modbus function code (e.g. 0x03).
        #   Value:     `RouterHandler` async callable.
        self._handlers: dict[int | None, dict[int, RouterHandler]] = {}

    def supports_unit_id(self, unit_id: int, /) -> bool:
        """Check if the handler supports the given unit ID."""
        return None in self._handlers or unit_id in self._handlers

    def register[T, PDU: BasePDU[Any]](
        self,
        pdu_class: type[PDU],
        *,
        unit_id: int | Iterable[int] | None = None,
    ) -> Callable[[Callable[[int, PDU], Awaitable[T]]], Callable[[int, PDU], Awaitable[T]]]:
        """Register a handler for a specific request PDU class and optional unit ID(s).

        Note:
            For Modbus RTU/ASCII (serial line), to handle broadcast requests, a handler
            must be explicitly registered for unit ID 0 (or register a default wildcard
            handler by omitting the unit_id parameter).

        """

        def decorator(handler: Callable[[int, PDU], Awaitable[T]]) -> Callable[[int, PDU], Awaitable[T]]:
            # Ensure pdu_class has function_code (since it should be a BasePDU subclass)
            func_code = pdu_class.function_code

            def add_handler(uid: int | None) -> None:
                if uid not in self._handlers:
                    self._handlers[uid] = {}

                if func_code in self._handlers[uid]:
                    msg = f"Handler for function code {func_code} and unit ID {uid} already registered"
                    raise ValueError(msg)

                self._handlers[uid][func_code] = handler

            if unit_id is None:
                add_handler(None)
            elif isinstance(unit_id, int):
                add_handler(unit_id)
            else:
                for uid in unit_id:
                    add_handler(uid)
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
        # First, try to find handlers for the specific unit ID
        func_handlers = self._handlers.get(unit_id)
        if func_handlers is None:
            # Fallback to the default (wildcard None) unit ID handlers
            func_handlers = self._handlers.get(None)

        if func_handlers is None:
            raise IllegalFunctionError(ExceptionCode.ILLEGAL_FUNCTION, request.function_code)

        handler = func_handlers.get(request.function_code)
        if handler is None:
            raise IllegalFunctionError(ExceptionCode.ILLEGAL_FUNCTION, request.function_code)

        return cast("T", await handler(unit_id, request))


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
