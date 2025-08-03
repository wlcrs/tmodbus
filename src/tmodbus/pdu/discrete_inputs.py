"""Read Coils PDU Module."""

from tmodbus.const import FunctionCode

from .coils import ReadCoilsPDU


class ReadDiscreteInputsPDU(ReadCoilsPDU):
    """Read Discrete Inputs PDU."""

    function_code = FunctionCode.READ_DISCRETE_INPUTS
