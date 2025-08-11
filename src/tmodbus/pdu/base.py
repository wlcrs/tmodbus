"""Base class for Modbus PDU (Protocol Data Unit) handling."""

from abc import ABC, abstractmethod
from typing import TypeVar

RT = TypeVar("RT")


class BaseModbusPDU[RT](ABC):
    """Base class for Modbus PDU (Protocol Data Unit) handling."""

    function_code: int
    rtu_response_data_length: int | None = None

    def __init__(self, address: int) -> None:
        """Initialize PDU with address.

        Args:
            address: Address on which the PDU operates

        """
        if not (0 <= address < 65536):
            msg = "Address must be between 0 and 65535."
            raise ValueError(msg)

        self.address = address

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

    @classmethod
    def get_expected_data_length(cls, data: bytes) -> int:
        """Get the expected number of bytes for the data part of the response PDU.

        This method should be implemented by subclasses to return the expected
        length of the response based on the specific PDU type.

        Returns:
            Expected length of the response PDU in bytes

        """
        # if a fixed length is defined for the response PDU, return it
        if cls.rtu_response_data_length is not None:
            return cls.rtu_response_data_length

        # otherwise, we assume that the first byte of the PDU-part of the response denotes
        # the total length of the PDU.
        # If this is not the case (ex. for function code 0x18), the subclass should override this method.
        return (
            1  # the first byte containing the total length of the PDU
            + data[0]
        )
