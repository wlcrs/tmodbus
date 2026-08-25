"""Base class for Modbus PDU (Protocol Data Unit) handling."""

from abc import ABC, abstractmethod
from typing import Self, TypeVar

from tmodbus.exceptions import FunctionCodeError, InvalidRequestError

RT = TypeVar("RT")


class BaseClientPDU[RT](ABC):
    """Base class that defines the functions needed to handle Modbus PDUs on the client-side."""

    function_code: int
    rtu_request_data_length: int | None = None
    rtu_response_data_length: int | None = None
    expects_response: bool = True

    @abstractmethod
    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        This method should be implemented by subclasses to convert the PDU
        into a byte representation suitable for transmission.
        """

    @abstractmethod
    def decode_response(self, response: bytes) -> RT:
        """Decode the response PDU.

        Args:
            response: Response PDU bytes

        Returns:
            Decoded response data, type depends on the specific PDU implementation

        """

    def get_broadcast_response(self) -> RT:
        """Get the response for a broadcast PDU."""
        msg = f"Function code {self.function_code:#04x} does not support broadcasting."
        raise InvalidRequestError(msg)

    @classmethod
    def get_expected_response_data_length(cls, data: bytes) -> int | None:
        """Get the expected number of bytes for the data part of the response PDU.

        This method should be implemented by subclasses to return the expected
        length of the response based on the specific PDU type.

        Returns:
            Expected length of the response PDU in bytes, or None if it cannot be determined yet.

        """
        # if a fixed length is defined for the response PDU, return it
        if cls.rtu_response_data_length is not None:
            return cls.rtu_response_data_length

        # otherwise, we assume that the first byte of the PDU-part of the response denotes
        # the total length of the PDU.
        # If this is not the case (ex. for function code 0x18), the subclass should override this method.
        if not data:
            return None  # length byte not received yet
        return (
            1  # the first byte containing the total length of the PDU
            + data[0]
        )


class BasePDU[RT](BaseClientPDU[RT]):
    """Base class that defines the functions needed to handle Modbus PDUs on both the client-side and server-side."""

    ### Server methods ###

    @classmethod
    @abstractmethod
    def decode_request(cls, request: bytes) -> Self:
        """Create an instance of this PDU from a request byte sequence."""

    @abstractmethod
    def encode_response(self, value: RT) -> bytes:
        """Convert the response value to bytes.

        Args:
            value: The value to encode in the response

        Returns:
            Bytes representation of the response PDU

        """

    @classmethod
    def get_expected_request_data_length(cls, data: bytes) -> int | None:
        """Get the expected number of bytes for the data part of the request PDU.

        This method should be implemented by subclasses to return the expected
        length of the request based on the specific PDU type.

        Returns:
            Expected length of the request PDU in bytes, or None if it cannot be determined yet.

        """
        # if a fixed length is defined for the request PDU, return it
        if cls.rtu_request_data_length is not None:
            return cls.rtu_request_data_length

        # otherwise, we assume that the first byte of the PDU-part of the response denotes
        # the total length of the PDU.
        # If this is not the case (ex. for function code 0x18), the subclass should override this method.
        if not data:
            return None  # length byte not received yet
        return (
            1  # the first byte containing the total length of the PDU
            + data[0]
        )


class BaseSubFunctionClientPDU[RT](BaseClientPDU[RT]):
    """Extends the BaseClientPDU to include sub-function code.

    Only the get_expected_response_data_length method is changed in this class.
    """

    sub_function_code: int
    sub_function_code_length: int = 1

    @classmethod
    def get_expected_response_data_length(cls, data: bytes) -> int | None:
        """Get the expected number of bytes for the data part of the response PDU.

        This method should be implemented by subclasses to return the expected
        length of the response based on the specific PDU type.

        Returns:
            Expected length of the response PDU in bytes, or None if it cannot be determined yet.

        """
        if len(data) < cls.sub_function_code_length:
            return None
        received_sub_func = int.from_bytes(data[: cls.sub_function_code_length], "big")

        if received_sub_func != cls.sub_function_code:
            msg = f"Expected sub-function code {cls.sub_function_code}, got {received_sub_func}"
            raise FunctionCodeError(msg, response_bytes=data)

        # if a fixed length is defined for the response PDU, return it
        if cls.rtu_response_data_length is not None:
            return cls.rtu_response_data_length

        # otherwise, we assume that the next byte contains the length of the remaining data
        if len(data) <= cls.sub_function_code_length:
            return None  # length byte not received yet
        return cls.sub_function_code_length + 1 + data[cls.sub_function_code_length]


class BaseSubFunctionPDU[RT](BaseSubFunctionClientPDU[RT], BasePDU[RT]):
    """Extends BasePDU to include sub-function code."""

    sub_function_code: int

    @classmethod
    def get_expected_request_data_length(cls, data: bytes) -> int | None:
        """Get the expected number of bytes for the data part of the request PDU.

        This method should be implemented by subclasses to return the expected
        length of the request based on the specific PDU type.

        Returns:
            Expected length of the request PDU in bytes, or None if it cannot be determined yet.

        """
        if len(data) < cls.sub_function_code_length:
            return None  # sub-function code not received yet
        received_sub_func = int.from_bytes(data[: cls.sub_function_code_length], "big")

        if received_sub_func != cls.sub_function_code:
            msg = f"Expected sub-function code {cls.sub_function_code}, got {received_sub_func}"
            raise InvalidRequestError(msg, request_bytes=data)

        # if a fixed length is defined for the request PDU, return it
        if cls.rtu_request_data_length is not None:
            return cls.rtu_request_data_length

        # otherwise, we assume that the next byte contains the length of the remaining data
        if len(data) <= cls.sub_function_code_length:
            return None  # length byte not received yet
        return cls.sub_function_code_length + 1 + data[cls.sub_function_code_length]
