import pytest

from tmodbus.pdu import get_pdu_class


def test_get_pdu_class():
    """Test getting PDU class by function code."""
    from tmodbus.const import FunctionCode

    # Test valid function code
    pdu_class = get_pdu_class(FunctionCode.READ_HOLDING_REGISTERS)
    assert pdu_class.__name__ == "ReadHoldingRegistersPDU"

    # Test valid function code as int
    pdu_class = get_pdu_class(0x03)  # FunctionCode.READ_HOLDING_REGISTERS
    assert pdu_class.__name__ == "ReadHoldingRegistersPDU"

    # Test unknown function code
    with pytest.raises(ValueError, match="Unknown function code: 99"):
        get_pdu_class(99)

    # Test unknown function code
    with pytest.raises(ValueError, match="Unsupported function code: 0x2b"):
        get_pdu_class(FunctionCode.ENCAPSULATED_INTERFACE_TRANSPORT)
