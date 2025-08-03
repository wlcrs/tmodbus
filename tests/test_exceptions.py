import pytest

from tmodbus.exceptions import ModbusResponseError


def test_modbus_response_error():
    """Test Modbus response error handling."""

    class TestError(ModbusResponseError):
        error_code = 0xAB

    test_error = TestError(0xAB, 0x02)
    assert test_error.error_code == 0xAB
    assert test_error.function_code == 0x02

    with pytest.raises(AssertionError):
        TestError(0x01, 0x02)
