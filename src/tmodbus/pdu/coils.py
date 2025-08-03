"""Read Coils PDU Module."""

import struct

from tmodbus.const import FunctionCode
from tmodbus.exceptions import InvalidResponseError

from .base import BaseModbusPDU


class ReadCoilsPDU(BaseModbusPDU):
    """Read Coils PDU."""

    function_code = FunctionCode.READ_COILS

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
        if not (1 <= quantity <= 2000):
            msg = "Quantity must be between 1 and 2000."
            raise ValueError(msg)

        self.quantity = quantity

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Read Coils PDU

        """
        return struct.pack(">BHH", self.function_code, self.address, self.quantity)

    def decode_response(self, response: bytes) -> list[bool]:
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

        if byte_count != (self.quantity + 7) // 8:
            msg = f"Invalid byte count: expected {(self.quantity + 7) // 8}, got {byte_count}"
            raise InvalidResponseError(msg)

        coils: list[bool] = []
        for byte in response[2:]:
            coils.extend([bool(byte & (1 << bit)) for bit in range(8)])

        return coils[: self.quantity]  # Ensure we return only the requested quantity


class WriteSingleCoilPDU(BaseModbusPDU):
    """Write Single Coil PDU."""

    function_code = FunctionCode.WRITE_SINGLE_COIL
    rtu_response_data_length = 3

    def __init__(
        self,
        address: int,
        value: bool,  # noqa: FBT001
    ) -> None:
        """Initialize Write Single Coil PDU.

        Args:
            address: Address of the coil to write
            value: Value to write (True for ON, False for OFF)

        Raises:
            ValueError: If address is invalid

        """
        super().__init__(address)
        self.value = value

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Write Single Coil PDU

        """
        coil_value = 0xFF00 if self.value else 0x0000
        return struct.pack(">BHH", self.function_code, self.address, coil_value)

    def decode_response(self, response: bytes) -> None:
        """Decode the response PDU.

        Args:
            response: Response PDU bytes

        Raises:
            InvalidResponseError: If response format is invalid

        """
        if response != self.encode_request():
            msg = "Expected response to match request"
            raise InvalidResponseError(msg)


class WriteMultipleCoilsPDU(BaseModbusPDU):
    """Write Multiple Coils PDU."""

    function_code = FunctionCode.WRITE_MULTIPLE_COILS

    def __init__(self, start_address: int, values: list[bool]) -> None:
        """Initialize Write Multiple Coils PDU.

        Args:
            start_address: Starting address of the coils to write
            values: List of boolean values representing the coil states

        Raises:
            ValueError: If start_address or values are invalid

        """
        super().__init__(start_address)
        if not (1 <= len(values) <= 0x07B0):  # 1968 coils max
            msg = "Number of coils must be between 1 and 1968."
            raise ValueError(msg)

        self.values = values

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Write Multiple Coils PDU

        """
        # Calculate required byte count
        byte_count = (len(self.values) + 7) // 8

        # Prepare data bytes
        data = bytearray(byte_count)
        for i, value in enumerate(self.values):
            if value:
                data[i // 8] |= 1 << (i % 8)

        return (
            struct.pack(
                ">BHHB",
                self.function_code,
                self.address,
                len(self.values),
                byte_count,
            )
            + data
        )

    def decode_response(self, response: bytes) -> None:
        """Decode the response PDU.

        Args:
            response: Response PDU bytes

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
