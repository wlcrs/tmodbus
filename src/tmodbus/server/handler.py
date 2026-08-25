"""Modbus Server Handler Protocol."""

from __future__ import annotations

import dataclasses
import functools
import inspect
import logging
from collections.abc import Awaitable, Callable, Iterable
from typing import TYPE_CHECKING, Any, Protocol, TypeGuard, cast

from tmodbus.const import EXCEPTION_RESPONSE_BIT, ExceptionCode
from tmodbus.exceptions import IllegalFunctionError, ModbusResponseError, SuppressResponseError
from tmodbus.pdu import BaseClientPDU, BasePDU

if TYPE_CHECKING:
    from cryptography import x509
    from typing_extensions import TypeIs

logger = logging.getLogger(__name__)


def is_server_pdu_class(pdu_class: type[BaseClientPDU[Any]]) -> TypeGuard[type[BasePDU[Any]]]:
    """Type guard to check if a PDU class implements server-side methods."""
    return issubclass(pdu_class, BasePDU)


@dataclasses.dataclass(frozen=True)
class RequestContext:
    """Metadata about the incoming Modbus request and its transport connection.

    Passed to handlers that implement the :class:`ContextAwareModbusHandler` protocol
    (i.e. handlers that declare a ``context`` parameter).

    This context container is designed to be extensible, allowing for both security
    and non-security metadata (e.g. peer IP address) to be passed cleanly.
    """

    peer_addr: tuple[Any, ...] | None = None
    """The remote IP address and port of the client (if available)."""

    client_cert: x509.Certificate | None = None
    """The parsed client TLS certificate (if available).

    Only populated when the connection is established over TLS (mbaps)
    with client certificate validation enabled.
    """


# A type alias for the type-erased underlying handler callable.
type RouterHandler = Callable[[int, Any], Awaitable[Any]]


@functools.cache
def _is_context_aware(fn: Any) -> bool:
    """Return ``True`` if *fn* can accept a third positional argument."""
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return False
    positional = 0
    for param in sig.parameters.values():
        if param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD):
            positional += 1
        elif param.kind is param.VAR_POSITIONAL:
            # *args can absorb the context argument
            return True
    return positional >= 3


def _handler_accepts_context(fn: Any) -> TypeIs[ContextAwareModbusHandler]:
    """Return ``True`` if *fn* accepts a third positional parameter.

    Uses :func:`inspect.signature` to inspect the callable's parameter list at
    runtime, enabling automatic injection of :class:`RequestContext` into
    handlers that accept it.

    Args:
        fn: Any callable (async function, class instance with ``__call__``, etc.)

    Returns:
        ``True`` if at least three positional parameters appear in the callable's signature.

    """
    return _is_context_aware(fn)


# A ModbusHandler is a protocol representing a callable that processes a request PDU
# and returns the response payload of the matching type.
class ModbusHandler(Protocol):
    """Protocol for plain Modbus request handlers."""

    def __call__[T](self, unit_id: int, request: BasePDU[T], /) -> Awaitable[T]:
        """Process a Modbus request and return the response value."""
        ...

    def supports_unit_id(self, _unit_id: int, /) -> bool:
        """Check if the handler supports the given unit ID."""
        return True


class ContextAwareModbusHandler(Protocol):
    """Protocol for Modbus request handlers that require transport/context details."""

    def __call__[T](
        self,
        unit_id: int,
        request: BasePDU[T],
        context: RequestContext,
        /,
    ) -> Awaitable[T]:
        """Process a Modbus request with transport context and return the response value."""
        ...

    def supports_unit_id(self, _unit_id: int, /) -> bool:
        """Check if the handler supports the given unit ID."""
        return True


#: Union type accepting either standard or context-aware request handlers.
type AnyModbusHandler = ModbusHandler | ContextAwareModbusHandler


class ModbusRequestRouter(ModbusHandler):
    """A type-safe dispatcher/router for Modbus requests."""

    def __init__(self) -> None:
        """Initialize the ModbusRequestRouter.

        This router acts as a centralized dispatcher for incoming Modbus request PDUs.
        It maps Modbus function codes to async handler functions with full static type
        safety.

        Handlers registered with the router may optionally accept a third positional
        parameter to receive connection metadata like peer address and TLS certificate
        information. The router detects this at registration time using signature
        inspection and injects it automatically.

        Examples:
            Creating and using a router for a Modbus server:

            .. code-block:: python

                from tmodbus.pdu import ReadHoldingRegistersPDU
                from tmodbus.server import AsyncTcpServer, ModbusRequestRouter
                from tmodbus.server.handler import RequestContext

                router = ModbusRequestRouter()


                # Plain handler — works for both plain TCP and TLS
                @router.register(ReadHoldingRegistersPDU)
                async def handle_read_holding_registers(
                    unit_id: int, request: ReadHoldingRegistersPDU
                ) -> list[int]:
                    return [42] * request.quantity


                # Context-aware handler — receives client address and certs
                from tmodbus.server.security import extract_modbus_role

                @router.register(ReadHoldingRegistersPDU, unit_id=2)
                async def handle_secure(
                    unit_id: int,
                    request: ReadHoldingRegistersPDU,
                    context: RequestContext,
                ) -> list[int]:
                    role = extract_modbus_role(context.client_cert) if context.client_cert else None
                    if role != "Operator":
                        raise IllegalFunctionError(request.function_code)
                    print(f"Request from: {context.peer_addr}")
                    return [42] * request.quantity


                # Pass the router as the handler to the Modbus server
                server = AsyncTcpServer(host="localhost", port=502, handler=router)
                await server.serve_forever()

        """
        # Map of registered handlers.
        #
        # Structure:
        #   Outer Key: `int | None` representing the unit ID (slave address).
        #              `None` acts as a wildcard fallback key for any unit ID.
        #   Inner Key: `(function_code, sub_function_code)` tuple. The sub-function
        #              code is `None` for PDUs without one (e.g. 0x03), so PDUs that
        #              share a function code (e.g. Diagnostics 0x08) route per
        #              sub-function.
        #   Value:     `RouterHandler` mapping that key to the handler.
        self._handlers: dict[int | None, dict[tuple[int, int | None], RouterHandler]] = {}

    def supports_unit_id(self, unit_id: int, /) -> bool:
        """Check if the handler supports the given unit ID."""
        return None in self._handlers or unit_id in self._handlers

    def register[T](
        self,
        pdu_class: type[BasePDU[T]],
        *,
        unit_id: int | Iterable[int] | None = None,
    ) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
        """Register a handler for a specific request PDU class and optional unit ID(s).

        The handler's signature is inspected dynamically on dispatch to determine
        whether to inject the :class:`RequestContext`.

        PDU classes with a ``sub_function_code`` attribute (e.g. the Diagnostics
        PDUs, which all share function code 0x08) are registered per sub-function,
        so each sub-function gets its own handler. A request for a sub-function
        without a handler is answered with an Illegal Function exception.

        Note:
            For Modbus RTU/ASCII (serial line), to handle broadcast requests, a handler
            must be explicitly registered for unit ID 0 (or register a default wildcard
            handler by omitting the unit_id parameter).

        """

        def decorator(handler: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
            # Ensure pdu_class has function_code (since it should be a BasePDU subclass)
            func_code = pdu_class.function_code
            sub_func_code: int | None = getattr(pdu_class, "sub_function_code", None)
            key = (func_code, sub_func_code)

            unit_ids: list[int | None] = [unit_id] if unit_id is None or isinstance(unit_id, int) else list(unit_id)

            # Validate the whole batch before mutating, so a failing call
            # leaves the router unchanged.
            seen: set[int | None] = set()
            for uid in unit_ids:
                if uid in seen or key in self._handlers.get(uid, {}):
                    sub_func = f" sub-function code {sub_func_code}" if sub_func_code is not None else ""
                    msg = f"Handler for function code {func_code}{sub_func} and unit ID {uid} already registered"
                    raise ValueError(msg)
                seen.add(uid)

            for uid in unit_ids:
                self._handlers.setdefault(uid, {})[key] = handler
            return handler

        return decorator

    async def __call__[T](
        self,
        unit_id: int,
        request: BasePDU[T],
        /,
        context: RequestContext | None = None,
    ) -> T:
        """Route the incoming Modbus request to its registered handler.

        Args:
            unit_id: The slave address / unit ID of the target device.
            request: The parsed Modbus request PDU.
            context: Optional connection and transport context details.

        Returns:
            The output payload returned by the registered handler, typed
            specifically to the request PDU.

        Raises:
            IllegalFunctionError: If no handler is registered for the function code
                (and sub-function code, if any) specified in the request PDU.

        """
        # First, try to find handlers for the specific unit ID
        func_handlers = self._handlers.get(unit_id)
        if func_handlers is None:
            # Fallback to the default (wildcard None) unit ID handlers
            func_handlers = self._handlers.get(None)

        if func_handlers is None:
            raise IllegalFunctionError(request.function_code)

        handler = func_handlers.get((request.function_code, getattr(request, "sub_function_code", None)))
        if handler is None:
            raise IllegalFunctionError(request.function_code)

        if _handler_accepts_context(handler):
            # Inject context
            ctx = context or RequestContext()
            return cast("T", await handler(unit_id, request, ctx))
        return cast("T", await handler(unit_id, request))


async def handle_modbus_request[T](
    unit_id: int,
    request: BasePDU[T],
    handler: AnyModbusHandler,
    *,
    context: RequestContext | None = None,
) -> bytes:
    """Handle a Modbus request using the given handler and encode the response.

    Uses runtime signature inspection to determine whether *handler* accepts a
    third positional parameter to receive context. If so, the connection
    :class:`RequestContext` is injected automatically.

    Args:
        unit_id: The slave address / unit id
        request: The parsed request PDU
        handler: The user-defined handler function or :class:`ModbusRequestRouter`
        context: Optional connection and request context details.

    Returns:
        The encoded response PDU (either normal or exception)

    """
    try:
        if _handler_accepts_context(handler):
            ctx = context or RequestContext()
            response_data = await handler(unit_id, request, ctx)
        else:
            response_data = await handler(unit_id, request)
        return request.encode_response(response_data)
    except SuppressResponseError:
        logger.debug(
            "Response explicitly suppressed by handler for unit_id %d, function %s",
            unit_id,
            request.function_code,
        )
        return b""
    except ModbusResponseError as e:
        logger.warning(
            "Modbus Exception %s (%s) for unit_id %d, function %s",
            e.error_code,
            e.__class__.__name__,
            unit_id,
            request.function_code,
        )
        return bytes([request.function_code | EXCEPTION_RESPONSE_BIT, e.error_code])
    except Exception:
        logger.exception("Unexpected error in Modbus handler for unit_id %d", unit_id)
        # For completely unexpected errors, we default to returning ServerDeviceFailure
        return bytes([request.function_code | EXCEPTION_RESPONSE_BIT, ExceptionCode.SERVER_DEVICE_FAILURE])


def handler_supports_unit_id(handler: AnyModbusHandler, unit_id: int) -> bool:
    """Return ``True`` if *handler* supports the given *unit_id*.

    If the handler does not have a ``supports_unit_id`` method, it is assumed
    to support all unit IDs (returns ``True``).

    """
    if hasattr(handler, "supports_unit_id"):
        return bool(handler.supports_unit_id(unit_id))
    return True
