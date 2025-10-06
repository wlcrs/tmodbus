"""Modbus Protocol Data Unit (PDU)."""

from typing import Any

from tmodbus.const import FunctionCode

from .base import BaseClientPDU, BasePDU, BaseSubFunctionClientPDU, BaseSubFunctionPDU
from .coils import ReadCoilsPDU, WriteMultipleCoilsPDU, WriteSingleCoilPDU
from .device import ReadDeviceIdentificationPDU, ReadDeviceIdentificationResponse
from .discrete_inputs import ReadDiscreteInputsPDU
from .holding_registers import (
    MaskWriteRegisterPDU,
    ReadHoldingRegistersPDU,
    ReadInputRegistersPDU,
    WriteMultipleRegistersPDU,
    WriteSingleRegisterPDU,
)
from .serial_line import ReportServerIdPDU, ServerIdResponse

function_code_to_pdu_map: dict[int, type[BaseClientPDU[Any]]] = {
    FunctionCode.READ_COILS: ReadCoilsPDU,
    FunctionCode.READ_DISCRETE_INPUTS: ReadDiscreteInputsPDU,
    FunctionCode.READ_HOLDING_REGISTERS: ReadHoldingRegistersPDU,
    FunctionCode.READ_INPUT_REGISTERS: ReadInputRegistersPDU,
    FunctionCode.WRITE_SINGLE_COIL: WriteSingleCoilPDU,
    FunctionCode.WRITE_SINGLE_REGISTER: WriteSingleRegisterPDU,
    FunctionCode.WRITE_MULTIPLE_COILS: WriteMultipleCoilsPDU,
    FunctionCode.WRITE_MULTIPLE_REGISTERS: WriteMultipleRegistersPDU,
    FunctionCode.REPORT_SERVER_ID: ReportServerIdPDU,
    FunctionCode.MASK_WRITE_REGISTER: MaskWriteRegisterPDU,
}

sub_function_code_to_pdu_map: dict[int, dict[int, type[BaseSubFunctionClientPDU[Any]]]] = {
    FunctionCode.ENCAPSULATED_INTERFACE_TRANSPORT: {
        ReadDeviceIdentificationPDU.sub_function_code: ReadDeviceIdentificationPDU,
    }
}


def register_pdu_class(pdu_class: type[BaseClientPDU[Any]]) -> None:
    """Register a PDU class for a specific function code.

    Args:
        pdu_class: PDU class to register

    """
    function_code = pdu_class.function_code
    if issubclass(pdu_class, BaseSubFunctionClientPDU):
        if existing_pdu_class := function_code_to_pdu_map.get(function_code):
            msg = (
                f"Function code {function_code:#04x} is already registered "
                f"for a non-subfunction PDU {existing_pdu_class.__name__}."
            )
            raise ValueError(msg)
        if function_code not in sub_function_code_to_pdu_map:
            sub_function_code_to_pdu_map[function_code] = {}

        sub_function_code = pdu_class.sub_function_code

        if sub_function_code in sub_function_code_to_pdu_map[function_code]:
            msg = (
                f"A PDU with function code {function_code:#04x}, "
                f"and sub-function code {sub_function_code:#04x} is already registered: "
                f"{sub_function_code_to_pdu_map[function_code][sub_function_code].__name__}."
            )
            raise ValueError(msg)

        sub_function_code_to_pdu_map[function_code][sub_function_code] = pdu_class
    else:  # Registering a normal PDU class
        if existing_sub_pdus := sub_function_code_to_pdu_map.get(function_code):
            existing_sub_pdus_list = ", ".join(
                f"{sub_function_code:#04x}: {c.__name__}" for sub_function_code, c in existing_sub_pdus.items()
            )
            msg = (
                f"Function code {function_code:#04x} is already registered with sub-functions: {existing_sub_pdus_list}"
            )
            raise ValueError(msg)

        if existing_pdu_class := function_code_to_pdu_map.get(function_code):
            msg = f"Function code {function_code:#02x} is already registered to {existing_pdu_class.__name__}."
            raise ValueError(msg)

        function_code_to_pdu_map[pdu_class.function_code] = pdu_class


def get_pdu_class(begin_bytes: bytes) -> type[BaseClientPDU[Any]]:
    """Get PDU class by function code.

    Args:
        begin_bytes: Beginning bytes of the PDU, starting with function code

    Returns:
        Corresponding PDU class

    Raises:
        ValueError: If function code is not supported

    """
    function_code = begin_bytes[0]
    if pdu_class := function_code_to_pdu_map.get(function_code):
        return pdu_class

    if sub_function_pdus := sub_function_code_to_pdu_map.get(function_code):
        sub_function_code = begin_bytes[1]
        try:
            return sub_function_pdus[sub_function_code]
        except KeyError:
            msg = f"Unsupported sub-function code: {sub_function_code:#02x} for function code {function_code:#02x}"
            raise ValueError(msg) from None

    msg = f"Unsupported function code: {function_code:#02x}"
    raise ValueError(msg)


__all__ = [
    "BaseClientPDU",
    "BasePDU",
    "BaseSubFunctionClientPDU",
    "BaseSubFunctionPDU",
    "MaskWriteRegisterPDU",
    "ReadCoilsPDU",
    "ReadDeviceIdentificationPDU",
    "ReadDeviceIdentificationResponse",
    "ReadDiscreteInputsPDU",
    "ReadHoldingRegistersPDU",
    "ReadInputRegistersPDU",
    "ReportServerIdPDU",
    "ServerIdResponse",
    "WriteMultipleCoilsPDU",
    "WriteMultipleRegistersPDU",
    "WriteSingleCoilPDU",
    "WriteSingleRegisterPDU",
    "register_pdu_class",
]
