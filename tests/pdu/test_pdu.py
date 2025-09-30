import pytest

from tmodbus.const import FunctionCode
from tmodbus.pdu import get_pdu_class


def test_get_pdu_class():
    """Test getting PDU class by function code."""
    # Test valid function code
    pdu_class = get_pdu_class(bytes([int(FunctionCode.READ_HOLDING_REGISTERS)]))
    assert pdu_class.__name__ == "ReadHoldingRegistersPDU"

    # Test valid function code as int
    pdu_class = get_pdu_class(bytes([0x03]))  # FunctionCode.READ_HOLDING_REGISTERS
    assert pdu_class.__name__ == "ReadHoldingRegistersPDU"

    # Test unknown function code
    with pytest.raises(ValueError, match="Unsupported function code: 0x99"):
        get_pdu_class(bytes([0x99]))

    # Test unknown function code
    with pytest.raises(ValueError, match="Unsupported function code: 0x18"):
        get_pdu_class(bytes([FunctionCode.READ_FIFO_QUEUE]))
