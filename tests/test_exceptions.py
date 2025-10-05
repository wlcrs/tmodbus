import pytest
from tmodbus.exceptions import (
    ModbusResponseError,
    error_code_to_exception_map,
    register_custom_exception,
)


def test_modbus_response_error() -> None:
    """Test Modbus response error handling."""

    class TestError(ModbusResponseError):
        error_code = 0xAB

    test_error = TestError(0xAB, 0x02)
    assert test_error.error_code == 0xAB
    assert test_error.function_code == 0x02

    with pytest.raises(AssertionError):
        TestError(0x01, 0x02)


def test_register_custom_exception() -> None:
    class CustomError(ModbusResponseError):
        error_code = 0xFE

    register_custom_exception(CustomError)
    assert error_code_to_exception_map[0xFE] is CustomError
    # Registering again should raise ValueError
    with pytest.raises(ValueError, match=r".* already registered."):
        register_custom_exception(CustomError)
