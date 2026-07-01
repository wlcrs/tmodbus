"""Exception status PDU Module (serial line only)."""

from tmodbus.const import FunctionCode
from tmodbus.exceptions import InvalidRequestError, InvalidResponseError
from tmodbus.pdu.base import BasePDU


class ReadExceptionStatusPDU(BasePDU[int]):
    """Read Exception Status PDU (Function Code 0x07)."""

    function_code: int = FunctionCode.READ_EXCEPTION_STATUS
    rtu_response_data_length = 1  # a single status byte follows the function code

    def encode_request(self) -> bytes:
        """Encode Read Exception Status request PDU.

        Returns:
            Encoded request PDU as bytes

        """
        return bytes([self.function_code])

    @classmethod
    def decode_request(cls, data: bytes) -> "ReadExceptionStatusPDU":
        """Decode Read Exception Status request PDU.

        Args:
            data: Request PDU data as bytes

        Returns:
            Decoded ReadExceptionStatus instance

        Raises:
            InvalidRequestError: If data length or function code is incorrect

        """
        if len(data) != 1:
            msg = f"Invalid Read Exception Status request length: {len(data)}. Expected 1."
            raise InvalidRequestError(msg, request_bytes=data)

        function_code = data[0]

        if function_code != cls.function_code:
            msg = f"Invalid function code: {function_code:#04x}. Expected {cls.function_code:#04x}."
            raise InvalidRequestError(msg, request_bytes=data)

        return cls()

    def encode_response(self, status: int) -> bytes:
        """Encode Read Exception Status response PDU.

        Args:
            status: Exception status (0-255)

        Returns:
            Encoded response PDU as bytes

        Raises:
            ValueError: If status is out of range

        """
        if not (0 <= status <= 0xFF):
            msg = f"Status {status} out of range (0-255)."
            raise ValueError(msg)

        return bytes([self.function_code, status])

    def decode_response(self, data: bytes) -> int:
        """Decode Read Exception Status response PDU.

        Args:
            data: Response PDU data as bytes

        Returns:
            Decoded exception status (0-255)

        Raises:
            InvalidResponseError: If data length or function code is incorrect

        """
        if len(data) != 2:
            msg = f"Invalid Read Exception Status response length: {len(data)}. Expected 2."
            raise InvalidResponseError(msg, response_bytes=data)

        function_code, status = data

        if function_code != self.function_code:
            msg = f"Invalid function code: {function_code:#04x}. Expected {self.function_code:#04x}."
            raise InvalidResponseError(msg, response_bytes=data)

        return status
