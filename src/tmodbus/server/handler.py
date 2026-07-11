"""Modbus Server Handler Protocol."""

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from tmodbus.const import ExceptionCode
from tmodbus.exceptions import ModbusResponseError
from tmodbus.pdu import BasePDU

logger = logging.getLogger(__name__)

# A ModbusService is a function that takes a unit_id and a PDU request, and returns the response payload
# or raises a ModbusResponseError.
type ModbusService = Callable[[int, BasePDU[Any]], Awaitable[Any]]


async def ModbusRequestHandler(unit_id: int, request: BasePDU[Any], handler: ModbusService) -> bytes:
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
