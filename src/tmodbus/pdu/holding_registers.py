"""Read Coils PDU Module."""

import struct

from tmodbus.const import FunctionCode
from tmodbus.exceptions import InvalidResponseError

from .base import BaseModbusPDU


class ReadHoldingRegistersPDU(BaseModbusPDU):
    """Read Holding Register PDU."""

    function_code = FunctionCode.READ_HOLDING_REGISTERS

    def __init__(self, start_address: int, quantity: int) -> None:
        """Initialize Read Coils PDU.

        Args:
            start_address: Starting address of the coils to read
            quantity: Number of coils to read
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
            Bytes representation of the Read Coils PDU

        """
        return struct.pack(">BHH", self.function_code, self.address, self.quantity)

    def decode_response(self, response: bytes) -> list[int]:
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
            raise InvalidResponseError(msg) from e

        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:02x}, received {function_code:02x}"
            raise InvalidResponseError(msg)

        if len(response) != 2 + byte_count:
            msg = f"Invalid response PDU length: expected {2 + byte_count}, got {len(response)}"
            raise InvalidResponseError(msg)

        if byte_count // 2 != self.quantity:
            msg = f"Invalid register count: expected {self.quantity}, got {byte_count // 2}"
            raise InvalidResponseError(msg)

        return [*struct.unpack_from(f">{'H' * (byte_count // 2)}", response, offset=2)]


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
            raise InvalidResponseError(msg)


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

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Write Multiple Registers PDU

        """
        byte_count = len(self.values) * 2
        return struct.pack(
            f">BHHB{'H' * len(self.values)}",
            self.function_code,
            self.address,
            len(self.values),
            byte_count,
            *self.values,
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
            len(self.values),
        )

        if response != expected_response:
            msg = "Device response does not match request"
            raise InvalidResponseError(msg)
