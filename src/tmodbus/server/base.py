"""Modbus Server Base Classes and Shared Utilities."""

from abc import ABC, abstractmethod
from typing import Any

from tmodbus.const import EXCEPTION_RESPONSE_BIT, ExceptionCode
from tmodbus.exceptions import InvalidRequestError
from tmodbus.pdu import (
    BaseClientPDU,
    BasePDU,
    get_pdu_class,
    get_subfunction_code_length,
    get_subfunction_pdu_class,
    is_function_code_for_subfunction_pdu,
)

from .handler import is_server_pdu_class


def get_server_pdu_class(pdu_bytes: bytes) -> type[BasePDU[Any]]:
    """Return the server-capable PDU class for *pdu_bytes*."""
    return get_server_pdu_class_from_request_bytes(pdu_bytes)


def get_server_pdu_class_from_request_bytes(pdu_bytes: bytes) -> type[BasePDU[Any]]:
    """Return the server-capable PDU class for *pdu_bytes*.

    Args:
        pdu_bytes: Raw PDU bytes starting with the function code.

    Raises:
        InvalidRequestError: If *pdu_bytes* is empty or too short for sub-function.
        ValueError: If the resolved PDU class is client-only.

    Returns:
        The resolved ``BasePDU`` subclass.

    """
    if not pdu_bytes:
        msg = "Empty PDU"
        raise InvalidRequestError(msg, request_bytes=pdu_bytes)

    function_code = pdu_bytes[0]
    raw_pdu_class: type[BaseClientPDU[Any]]
    if is_function_code_for_subfunction_pdu(function_code):
        # We assume all subfunction PDU's will report the same number of bytes for the subfunction code.
        subfunction_code_length = get_subfunction_code_length(function_code)
        if len(pdu_bytes) < 1 + subfunction_code_length:
            msg = "Missing sub-function code"
            raise InvalidRequestError(msg, request_bytes=pdu_bytes)
        sub_function_code = int.from_bytes(pdu_bytes[1 : 1 + subfunction_code_length], "big")
        raw_pdu_class = get_subfunction_pdu_class(function_code, sub_function_code)
    else:
        raw_pdu_class = get_pdu_class(function_code)

    if not is_server_pdu_class(raw_pdu_class):
        msg = f"PDU class {raw_pdu_class.__name__} does not implement server methods"
        raise ValueError(msg)

    return raw_pdu_class


def get_server_pdu_class_from_buffer(buffer: bytearray) -> type[BasePDU[Any]] | None:
    """Return the server-capable PDU class from a partial receive buffer.

    Used by serial/stream transports (RTU, RTU-over-TCP) that accumulate raw
    bytes incrementally.  The caller should pass the *entire* buffer so that
    the sub-function byte at ``buffer[2]`` can be inspected.

    Args:
        buffer: Accumulated receive buffer beginning with the unit-id byte.

    Raises:
        ValueError: If the resolved PDU class does not implement server-side
            methods (i.e. is a client-only PDU).

    Returns:
        The resolved ``BasePDU`` subclass, or ``None`` when the buffer does
        not yet contain the function code or sub-function code byte.

    """
    if len(buffer) < 2:
        return None

    function_code = buffer[1]
    pdu_class: type[BaseClientPDU[Any]]
    if is_function_code_for_subfunction_pdu(function_code):
        subfunction_code_length = get_subfunction_code_length(function_code)
        if len(buffer) < 2 + subfunction_code_length:
            return None
        sub_function_code = int.from_bytes(buffer[2 : 2 + subfunction_code_length], "big")
        pdu_class = get_subfunction_pdu_class(function_code, sub_function_code)
    else:
        pdu_class = get_pdu_class(function_code)

    if not is_server_pdu_class(pdu_class):
        msg = f"PDU class {pdu_class.__name__} does not implement server methods"
        raise ValueError(msg)

    return pdu_class


def build_decode_error_response(function_code: int, error: Exception) -> bytes:
    """Build the exception-response PDU for a request that failed to decode.

    ``InvalidRequestError`` means the function code is supported but the request
    data is malformed, so per the Modbus specification the server answers
    ILLEGAL_DATA_VALUE.  Any other error means the (sub-)function code itself is
    unknown or unsupported, which is answered with ILLEGAL_FUNCTION.

    Args:
        function_code: Function code of the offending request.
        error: The exception raised while resolving or decoding the request.

    Returns:
        The two-byte exception-response PDU.

    """
    exception_code = (
        ExceptionCode.ILLEGAL_DATA_VALUE if isinstance(error, InvalidRequestError) else ExceptionCode.ILLEGAL_FUNCTION
    )
    return bytes([function_code | EXCEPTION_RESPONSE_BIT, exception_code])


class AsyncBaseServer(ABC):
    """Abstract base class for all async Modbus server implementations.

    Concrete server classes (``AsyncTcpServer``, ``AsyncRtuServer``, etc.)
    inherit from this class and implement the three lifecycle methods.

    The shared contract allows transport-agnostic code to start, stop, and
    run any server without knowing which transport is in use::

        server: AsyncBaseServer = AsyncTcpServer(host="0.0.0.0", handler=router)
        await server.serve_forever()

    """

    @abstractmethod
    async def start(self) -> None:
        """Bind / open the underlying transport and begin accepting requests.

        After this call the server is actively processing incoming data.
        This method must be idempotent with respect to already-started
        servers (i.e. calling it a second time should not raise).
        """

    @abstractmethod
    async def stop(self) -> None:
        """Stop the server and release all transport resources.

        Any in-flight request processing should be allowed to finish (or
        cancelled gracefully) before this method returns.
        """

    @abstractmethod
    async def serve_forever(self) -> None:
        """Start the server and block until cancelled.

        Equivalent to calling :meth:`start` followed by waiting indefinitely.
        Implementations should suppress ``asyncio.CancelledError`` internally
        so that callers can simply ``await server.serve_forever()`` inside a
        task and cancel the task to stop the server.
        """
