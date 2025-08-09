"""Exceptions."""

from typing import Any

from .const import ExceptionCode


class TModbusError(Exception):
    """Base exception class for ModbusLink library."""


class ModbusConnectionError(TModbusError):
    """Connection error exception.

    Raised when unable to establish or maintain connection with Modbus device.
    """

    bytes_read: bytes

    def __init__(self, *args: Any, bytes_read: bytes | None = None, **kwargs: Any) -> None:
        """Initialize RTUFrameError."""
        super().__init__(*args, **kwargs)
        self.bytes_read = bytes_read or b""


class InvalidResponseError(TModbusError):
    """Invalid response error exception.

    Raised when received response format is incorrect or unexpected.
    """

    bytes_read: bytes

    def __init__(self, *args: Any, bytes_read: bytes, **kwargs: Any) -> None:
        """Initialize RTUFrameError."""
        super().__init__(*args, **kwargs)
        self.bytes_read = bytes_read


class RTUFrameError(InvalidResponseError):
    """RTU frame error exception.

    Raised when there is a framing error in the received RTU frame.
    """


class CRCError(InvalidResponseError):
    """CRC validation error exception.

    Raised when CRC validation of received data frame fails.
    """


class HeaderMismatchError(InvalidResponseError):
    """Header mismatch error exception.

    Raised when the header of the received response does not match the request.
    """


class FunctionCodeError(InvalidResponseError):
    """Function code error exception.

    Raised when the function code in the response does not match the request.
    """


class ModbusResponseError(TModbusError):
    """Base class for all Modbus exception response."""

    error_code: int

    def __init__(self, error_code: int, function_code: int) -> None:
        """Initialize ModbusResponseError.

        Args:
            error_code: Error code from the Modbus exception response
            function_code: Function code of the request that caused the exception

        """
        super().__init__(f"Modbus Exception {error_code:02x} for function code {function_code:02x}")
        assert self.error_code == error_code  # noqa: S101
        self.function_code = function_code


class IllegalFunctionError(ModbusResponseError):
    """The function code received in the request is not an allowable action for the server."""

    error_code = ExceptionCode.ILLEGAL_FUNCTION


class IllegalDataAddressError(ModbusResponseError):
    """The data address received in the request is not an allowable address for the server."""

    error_code = ExceptionCode.ILLEGAL_DATA_ADDRESS


class IllegalDataValueError(ModbusResponseError):
    """The value contained in the request data field is not an allowable value for the server."""

    error_code = ExceptionCode.ILLEGAL_DATA_VALUE


class ServerDeviceFailureError(ModbusResponseError):
    """An unrecoverable error occurred."""

    error_code = ExceptionCode.SERVER_DEVICE_FAILURE


class AcknowledgeError(ModbusResponseError):
    """Acknowledge error.

    The server has accepted the requests and it processing it,
    but a long duration of time will be required to do so.
    """

    error_code = ExceptionCode.ACKNOWLEDGE


class ServerDeviceBusyError(ModbusResponseError):
    """The server is engaged in a long-duration program command."""

    error_code = ExceptionCode.SERVER_DEVICE_BUSY


class MemoryParityError(ModbusResponseError):
    """The server attempted to read record file, but detected a parity error in memory."""

    error_code = ExceptionCode.MEMORY_PARITY_ERROR


class GatewayPathUnavailableError(ModbusResponseError):
    """The gateway is probably misconfigured or overloaded."""

    error_code = ExceptionCode.GATEWAY_PATH_UNAVAILABLE


class GatewayTargetDeviceFailedToRespondError(ModbusResponseError):
    """Didn't get a response from target device."""

    error_code = ExceptionCode.GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND


error_code_to_exception_map: dict[int, type[ModbusResponseError]] = {
    IllegalFunctionError.error_code: IllegalFunctionError,
    IllegalDataAddressError.error_code: IllegalDataAddressError,
    IllegalDataValueError.error_code: IllegalDataValueError,
    ServerDeviceFailureError.error_code: ServerDeviceFailureError,
    AcknowledgeError.error_code: AcknowledgeError,
    ServerDeviceBusyError.error_code: ServerDeviceBusyError,
    MemoryParityError.error_code: MemoryParityError,
    GatewayPathUnavailableError.error_code: GatewayPathUnavailableError,
    GatewayTargetDeviceFailedToRespondError.error_code: GatewayTargetDeviceFailedToRespondError,
}
