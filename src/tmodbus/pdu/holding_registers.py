"""Holding/Input Registers PDU Module."""

import struct
from typing import Self

from tmodbus.const import FunctionCode
from tmodbus.exceptions import InvalidRequestError, InvalidResponseError

from .base import BasePDU


class RawReadHoldingRegistersPDU(BasePDU[bytes]):
    """Read Holding Register as raw bytes PDU implementation."""

    function_code = FunctionCode.READ_HOLDING_REGISTERS

    def __init__(self, start_address: int, quantity: int) -> None:
        """Initialize Read Holding Registers PDU.

        Args:
            start_address: Starting address of the registers to read
            quantity: Number of registers to read
            unit_id: Unit ID of the Modbus device

        Raises:
            ValueError: If start_address or quantity is invalid

        """
        if not (0 <= start_address < 65536):
            msg = "Address must be between 0 and 65535."
            raise ValueError(msg)
        self.start_address = start_address

        if not (1 <= quantity <= 125):
            msg = "Quantity must be between 1 and 125."
            raise ValueError(msg)
        self.quantity = quantity

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Read Holding Registers PDU

        """
        return struct.pack(">BHH", self.function_code, self.start_address, self.quantity)

    def decode_response(self, response: bytes) -> bytes:
        """Decode the response PDU.

        Args:
            response: Response PDU bytes

        Returns:
            List of boolean values representing the coil states

        Raises:
            ValueError: If response format is invalid

        """
        # response format: function code + byte count + data
        try:
            function_code, byte_count = struct.unpack_from(">BB", response)
        except struct.error as e:
            msg = "Expected response to start with function code and byte count"
            raise InvalidResponseError(msg, response_bytes=response) from e

        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:#04x}, received {function_code:#04x}"
            raise InvalidResponseError(msg, response_bytes=response)

        if len(response) != 2 + byte_count:
            msg = f"Invalid response PDU length: expected {2 + byte_count}, got {len(response)}"
            raise InvalidResponseError(msg, response_bytes=response)

        if byte_count // 2 != self.quantity:
            msg = f"Invalid register count: expected {self.quantity}, got {byte_count // 2}"
            raise InvalidResponseError(msg, response_bytes=response)

        return response[2:]  # Return the data part of the response

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode Read Holding Registers Request PDU.

        Args:
            request: The request bytes.

        Returns:
            RawReadHoldingRegistersPDU instance created from the request.

        """
        try:
            function_code, address, quantity = struct.unpack(">BHH", request)
        except struct.error as e:
            msg = "Expected request to start with function code, address, and quantity"
            raise InvalidRequestError(msg, request_bytes=request) from e

        if function_code != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {function_code:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls(address, quantity)

    def encode_response(self, value: bytes) -> bytes:
        """Encode the response PDU with raw bytes.

        Args:
            value: Raw bytes representing register data.

        Returns:
            Bytes representation of the Read Holding Registers response PDU.

        """
        return struct.pack(">BB", self.function_code, len(value)) + value


class ReadHoldingRegistersPDU(BasePDU[list[int]]):
    """Read Holding Register PDU."""

    function_code = FunctionCode.READ_HOLDING_REGISTERS

    def __init__(self, start_address: int, quantity: int) -> None:
        """Initialize Read Holding Registers PDU.

        Args:
            start_address: Starting address of the registers to read
            quantity: Number of registers to read

        Raises:
            ValueError: If start_address or quantity is invalid

        """
        self.raw_pdu = RawReadHoldingRegistersPDU(start_address, quantity)

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Read Holding Registers PDU

        """
        return self.raw_pdu.encode_request()

    def decode_response(self, response: bytes) -> list[int]:
        """Decode the response PDU.

        Args:
            response: Response PDU bytes

        Returns:
            List of integers representing the register values

        Raises:
            ValueError: If response format is invalid

        """
        response_bytes = self.raw_pdu.decode_response(response)

        return [*struct.unpack(f">{'H' * (len(response_bytes) // 2)}", response_bytes)]

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode Read Holding Registers Request PDU.

        Args:
            request: The request bytes.

        Returns:
            ReadHoldingRegistersPDU instance created from the request.

        """
        try:
            function_code, address, quantity = struct.unpack(">BHH", request)
        except struct.error as e:
            msg = "Expected request to start with function code, address, and quantity"
            raise InvalidRequestError(msg, request_bytes=request) from e

        if function_code != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {function_code:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls(address, quantity)

    def encode_response(self, value: list[int]) -> bytes:
        """Encode the response PDU with register values.

        Args:
            value: List of register values (unsigned 16-bit).

        Returns:
            Bytes representation of the Read Holding Registers response PDU.

        """
        data = struct.pack(f">{'H' * len(value)}", *value)
        return struct.pack(">BB", self.function_code, len(data)) + data


class RawReadInputRegistersPDU(RawReadHoldingRegistersPDU):
    """Raw Read Input Registers PDU.

    Inherits from ReadHoldingRegistersPDU, as the structure is the same.
    Only the function code differs.
    """

    function_code = FunctionCode.READ_INPUT_REGISTERS


class ReadInputRegistersPDU(ReadHoldingRegistersPDU):
    """Read Input Registers PDU.

    Inherits from ReadHoldingRegistersPDU, as the structure is the same.
    Only the function code differs.
    """

    function_code = FunctionCode.READ_INPUT_REGISTERS

    def __init__(self, start_address: int, quantity: int) -> None:
        """Initialize Read Holding Registers PDU.

        Args:
            start_address: Starting address of the registers to read
            quantity: Number of registers to read

        Raises:
            ValueError: If start_address or quantity is invalid

        """
        super(ReadHoldingRegistersPDU, self).__init__()
        self.raw_pdu = RawReadInputRegistersPDU(start_address, quantity)

    # decode_request and encode_response inherited from ReadHoldingRegistersPDU


class WriteSingleRegisterPDU(BasePDU[int]):
    """Write Single Register PDU."""

    function_code = FunctionCode.WRITE_SINGLE_REGISTER
    rtu_response_data_length = 4  # address (2) + value (2)

    def __init__(self, address: int, value: int) -> None:
        """Initialize Write Single Register PDU.

        Args:
            address: Address of the register to write
            value: Value to write to the register

        Raises:
            ValueError: If address or value is invalid

        """
        if not (0 <= address < 65536):
            msg = "Address must be between 0 and 65535."
            raise ValueError(msg)
        self.address = address

        if not (0 <= value < 65536):
            msg = "Value must be between 0 and 65535."
            raise ValueError(msg)
        self.value = value

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Write Single Register PDU

        """
        return struct.pack(">BHH", self.function_code, self.address, self.value)

    def decode_response(self, response: bytes) -> int:
        """Decode the response PDU.

        Args:
            response: Response PDU bytes

        Returns:
            None

        Raises:
            InvalidResponseError: If response format is invalid

        """
        if response != self.encode_request():
            msg = "Expected response to match request"
            raise InvalidResponseError(msg, response_bytes=response)
        return self.value

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode Write Single Register Request PDU.

        Args:
            request: The request bytes.

        Returns:
            WriteSingleRegisterPDU instance created from the request.

        """
        try:
            function_code, address, value = struct.unpack(">BHH", request)
        except struct.error as e:
            msg = "Expected request to start with function code, address, and value"
            raise InvalidRequestError(msg, request_bytes=request) from e

        if function_code != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {function_code:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls(address, value)

    def encode_response(self, value: int) -> bytes:  # type: ignore[override]
        """Encode the response PDU.

        Returns:
            Bytes representation of the Write Single Register response PDU (echo).

        """
        return struct.pack(">BHH", self.function_code, self.address, value)


class RawWriteMultipleRegistersPDU(BasePDU[int]):
    """Write Multiple Registers PDU."""

    function_code = FunctionCode.WRITE_MULTIPLE_REGISTERS
    rtu_response_data_length = 5

    def __init__(self, start_address: int, content: bytes) -> None:
        """Initialize Write Multiple Registers PDU.

        Args:
            address: Address of the first register to write
            content: Bytes content to write to the registers

        Raises:
            ValueError: If address or content is invalid

        """
        if not (0 <= start_address < 65536):
            msg = "Address must be between 0 and 65535."
            raise ValueError(msg)
        self.start_address = start_address

        if len(content) == 0:
            msg = "Content must not be empty."
            raise ValueError(msg)

        if len(content) > 2 * 123:
            msg = "Content exceeds maximum length."
            raise ValueError(msg)

        if len(content) % 2 != 0:
            content += b"\x00"  # Pad with zero if odd length

        self.content = content

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Write Multiple Registers PDU

        """
        byte_count = len(self.content)
        number_of_registers = byte_count // 2

        return (
            struct.pack(
                ">BHHB",
                self.function_code,
                self.start_address,
                number_of_registers,
                byte_count,
            )
            + self.content
        )

    def decode_response(self, response: bytes) -> int:
        """Verify the response PDU.

        Args:
            response: Response PDU bytes

        Returns:
            Number of registers written to

        Raises:
            InvalidResponseError: If response format is invalid

        """
        # Verify response: function code + starting address + quantity
        expected_response = struct.pack(
            ">BHH",
            self.function_code,
            self.start_address,
            len(self.content) // 2,  # number of registers written
        )

        if response != expected_response:
            msg = "Device response does not match request"
            raise InvalidResponseError(msg, response_bytes=response)
        return len(self.content) // 2  # Return number of registers written

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode Write Multiple Registers Request PDU.

        Args:
            request: The request bytes.

        Returns:
            RawWriteMultipleRegistersPDU instance created from the request.

        """
        if len(request) < 6:
            msg = "Request too short for Write Multiple Registers"
            raise InvalidRequestError(msg, request_bytes=request)

        function_code, start_address, quantity, byte_count = struct.unpack(">BHHB", request[:6])

        if function_code != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {function_code:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        if byte_count % 2 != 0:
            msg = "Byte count must be even for register values"
            raise InvalidRequestError(msg, request_bytes=request)

        if quantity != byte_count // 2:
            msg = f"Invalid register count: expected {byte_count // 2}, got {quantity}"
            raise InvalidRequestError(msg, request_bytes=request)

        content = request[6:]
        if len(content) != byte_count:
            msg = f"Invalid data length: expected {byte_count}, got {len(content)}"
            raise InvalidRequestError(msg, request_bytes=request)
        return cls(start_address, content)

    def encode_response(self, value: int) -> bytes:
        """Encode the response PDU.

        Args:
            value: the number of registers that has been written to.

        Returns:
            Bytes representation of the Write Multiple Registers response PDU.

        """
        return struct.pack(
            ">BHH",
            self.function_code,
            self.start_address,
            value,
        )


class WriteMultipleRegistersPDU(BasePDU[int]):
    """Write Multiple Registers PDU."""

    function_code = FunctionCode.WRITE_MULTIPLE_REGISTERS
    rtu_response_data_length = 4  # address (2) + quantity (2)

    def __init__(self, start_address: int, values: list[int]) -> None:
        """Initialize Write Multiple Registers PDU.

        Args:
            address: Address of the first register to write
            values: List of values to write to the registers

        Raises:
            ValueError: If address or values are invalid

        """
        if not (0 <= start_address < 65536):
            msg = "Address must be between 0 and 65535."
            raise ValueError(msg)
        self.start_adress = start_address

        if not (1 <= len(values) <= 123):
            msg = "Number of registers must be between 1 and 123."
            raise ValueError(msg)

        for value in values:
            if not (0 <= value < 65536):
                msg = f"Value must be between 0 and 65535: {value}"
                raise ValueError(msg)

        self.values = values

        self.raw_pdu = RawWriteMultipleRegistersPDU(start_address, struct.pack(f">{'H' * len(values)}", *values))

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Write Multiple Registers PDU

        """
        return self.raw_pdu.encode_request()

    def decode_response(self, response: bytes) -> int:
        """Verify the response PDU.

        Args:
            response: Response PDU bytes

        Returns:
            None

        Raises:
            InvalidResponseError: If response format is invalid

        """
        return self.raw_pdu.decode_response(response)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode Write Multiple Registers Request PDU.

        Args:
            request: The request bytes.

        Returns:
            WriteMultipleRegistersPDU instance created from the request.

        """
        raw = RawWriteMultipleRegistersPDU.decode_request(request)
        # Convert content bytes to list of ints
        values = list(struct.unpack(f">{'H' * (len(raw.content) // 2)}", raw.content))
        return cls(raw.start_address, values)

    def encode_response(self, value: int) -> bytes:
        """Encode the response PDU.

        Returns:
            Bytes representation of the Write Multiple Registers response PDU.

        """
        return self.raw_pdu.encode_response(value)
