"""Read Coils PDU Module."""

import struct

from tmodbus.const import FunctionCode
from tmodbus.exceptions import InvalidResponseError

from .base import BaseModbusPDU


class RawReadHoldingRegistersPDU(BaseModbusPDU):
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
        super().__init__(start_address)
        if not (1 <= quantity <= 125):
            msg = "Quantity must be between 1 and 125."
            raise ValueError(msg)

        self.quantity = quantity

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Read Holding Registers PDU

        """
        return struct.pack(">BHH", self.function_code, self.address, self.quantity)

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
            msg = f"Invalid function code: expected {self.function_code:02x}, received {function_code:02x}"
            raise InvalidResponseError(msg, response_bytes=response)

        if len(response) != 2 + byte_count:
            msg = f"Invalid response PDU length: expected {2 + byte_count}, got {len(response)}"
            raise InvalidResponseError(msg, response_bytes=response)

        if byte_count // 2 != self.quantity:
            msg = f"Invalid register count: expected {self.quantity}, got {byte_count // 2}"
            raise InvalidResponseError(msg, response_bytes=response)

        return response[2:]  # Return the data part of the response


class ReadHoldingRegistersPDU(BaseModbusPDU):
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
        super().__init__(start_address)
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


class ReadInputRegistersPDU(ReadHoldingRegistersPDU):
    """Read Input Registers PDU.

    Inherits from ReadHoldingRegistersPDU, as the structure is the same.
    Only the function code differs.
    """

    function_code = FunctionCode.READ_INPUT_REGISTERS


class WriteSingleRegisterPDU(BaseModbusPDU):
    """Write Single Register PDU."""

    function_code = FunctionCode.WRITE_SINGLE_REGISTER

    def __init__(self, address: int, value: int) -> None:
        """Initialize Write Single Register PDU.

        Args:
            address: Address of the register to write
            value: Value to write to the register

        Raises:
            ValueError: If address or value is invalid

        """
        super().__init__(address)
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

    def decode_response(self, response: bytes) -> None:
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


class RawWriteMultipleRegistersPDU(BaseModbusPDU):
    """Write Multiple Registers PDU."""

    function_code = FunctionCode.WRITE_MULTIPLE_REGISTERS

    def __init__(self, start_address: int, content: bytes) -> None:
        """Initialize Write Multiple Registers PDU.

        Args:
            address: Address of the first register to write
            content: Bytes content to write to the registers

        Raises:
            ValueError: If address or content is invalid

        """
        super().__init__(start_address)

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
                self.address,
                number_of_registers,
                byte_count,
            )
            + self.content
        )

    def decode_response(self, response: bytes) -> None:
        """Verify the response PDU.

        Args:
            response: Response PDU bytes

        Returns:
            None

        Raises:
            InvalidResponseError: If response format is invalid

        """
        # Verify response: function code + starting address + quantity
        expected_response = struct.pack(
            ">BHH",
            self.function_code,
            self.address,
            len(self.content) // 2,  # number of registers written
        )

        if response != expected_response:
            msg = "Device response does not match request"
            raise InvalidResponseError(msg, response_bytes=response)


class WriteMultipleRegistersPDU(BaseModbusPDU):
    """Write Multiple Registers PDU."""

    function_code = FunctionCode.WRITE_MULTIPLE_REGISTERS

    def __init__(self, start_address: int, values: list[int]) -> None:
        """Initialize Write Multiple Registers PDU.

        Args:
            address: Address of the first register to write
            values: List of values to write to the registers

        Raises:
            ValueError: If address or values are invalid

        """
        super().__init__(start_address)
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

    def decode_response(self, response: bytes) -> None:
        """Verify the response PDU.

        Args:
            response: Response PDU bytes

        Returns:
            None

        Raises:
            InvalidResponseError: If response format is invalid

        """
        return self.raw_pdu.decode_response(response)
