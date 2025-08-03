"""Modbus Protocol Data Unit (PDU)."""

from tmodbus.const import FunctionCode

from .base import BaseModbusPDU
from .coils import ReadCoilsPDU, WriteMultipleCoilsPDU, WriteSingleCoilPDU
from .discrete_inputs import ReadDiscreteInputsPDU
from .holding_registers import (
    ReadHoldingRegistersPDU,
    ReadInputRegistersPDU,
    WriteMultipleRegistersPDU,
    WriteSingleRegisterPDU,
)

function_code_to_pdu_map = {
    FunctionCode.READ_COILS: ReadCoilsPDU,
    FunctionCode.READ_DISCRETE_INPUTS: ReadDiscreteInputsPDU,
    FunctionCode.READ_HOLDING_REGISTERS: ReadHoldingRegistersPDU,
    FunctionCode.READ_INPUT_REGISTERS: ReadInputRegistersPDU,
    FunctionCode.WRITE_SINGLE_COIL: WriteSingleCoilPDU,
    FunctionCode.WRITE_SINGLE_REGISTER: WriteSingleRegisterPDU,
    FunctionCode.WRITE_MULTIPLE_COILS: WriteMultipleCoilsPDU,
    FunctionCode.WRITE_MULTIPLE_REGISTERS: WriteMultipleRegistersPDU,
}


def get_pdu_class(function_code: FunctionCode | int) -> type[BaseModbusPDU]:
    """Get PDU class by function code.

    Args:
        function_code: Modbus function code

    Returns:
        Corresponding PDU class

    Raises:
        ValueError: If function code is not supported
    """
    if isinstance(function_code, int):
        try:
            function_code = FunctionCode(function_code)
        except ValueError:
            msg = f"Unknown function code: {function_code}"
            raise ValueError(msg) from None

    try:
        return function_code_to_pdu_map[function_code]
    except KeyError:
        # If the function code is not in the map, raise an error
        # This allows for future extensibility if new function codes are added
        msg = f"Unsupported function code: {function_code:#02x}"
        raise ValueError(msg) from None


__all__ = [
    "BaseModbusPDU",
    "ReadCoilsPDU",
    "ReadDiscreteInputsPDU",
    "ReadHoldingRegistersPDU",
    "ReadInputRegistersPDU",
    "WriteMultipleCoilsPDU",
    "WriteMultipleRegistersPDU",
    "WriteSingleCoilPDU",
    "WriteSingleRegisterPDU",
]
