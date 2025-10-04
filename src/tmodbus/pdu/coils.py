"""Read Coils PDU Module."""

import struct
from typing import Self

from tmodbus.const import FunctionCode
from tmodbus.exceptions import InvalidRequestError, InvalidResponseError

from .base import BasePDU


class ReadCoilsPDU(BasePDU[list[bool]]):
    """Read Coils PDU."""

    function_code = FunctionCode.READ_COILS

    def __init__(self, start_address: int, quantity: int) -> None:
        """Initialize Read Coils PDU.

        Args:
            start_address: Starting address of the coils to read
            quantity: Number of coils to read

        Raises:
            ValueError: If start_address or quantity is invalid

        """
        if not (0 <= start_address < 65536):
            msg = "Address must be between 0 and 65535."
            raise ValueError(msg)
        self.start_address = start_address

        if not (1 <= quantity <= 2000):
            msg = "Quantity must be between 1 and 2000."
            raise ValueError(msg)
        self.quantity = quantity

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Read Coils PDU

        """
        return struct.pack(">BHH", self.function_code, self.start_address, self.quantity)

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
            raise InvalidResponseError(msg, response_bytes=response) from e

        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:#04x}, received {function_code:#04x}"
            raise InvalidResponseError(msg, response_bytes=response)

        if len(response) != 2 + byte_count:
            msg = f"Invalid response PDU length: expected {2 + byte_count}, got {len(response)}"
            raise InvalidResponseError(msg, response_bytes=response)

        if byte_count != (self.quantity + 7) // 8:
            msg = f"Invalid byte count: expected {(self.quantity + 7) // 8}, got {byte_count}"
            raise InvalidResponseError(msg, response_bytes=response)

        coils: list[bool] = []
        for byte in response[2:]:
            coils.extend([bool(byte & (1 << bit)) for bit in range(8)])

        return coils[: self.quantity]  # Ensure we return only the requested quantity

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode Read Coils Request PDU.

        Args:
            request: the request bytes.

        Returns:
            ReadCoilsPDU: The decoded Read Coils Request PDU.

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

    def encode_response(self, value: list[bool]) -> bytes:
        """Convert PDU to bytes.

        Args:
            value: List of boolean values representing the coil states

        Returns:
            Bytes representation of the Read Coils Response PDU

        """
        byte_count = (len(value) + 7) // 8
        data = bytearray(byte_count)
        for i, v in enumerate(value):
            if v:
                data[i // 8] |= 1 << (i % 8)

        return (
            struct.pack(
                ">BB",
                self.function_code,
                byte_count,
            )
            + data
        )


class WriteSingleCoilPDU(BasePDU[bool]):
    """Write Single Coil PDU."""

    function_code = FunctionCode.WRITE_SINGLE_COIL
    rtu_response_data_length = 4  # address (2) + value (2)

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
        super().__init__()
        self.address = address
        self.value = value

    def encode_request(self) -> bytes:
        """Convert PDU to bytes.

        Returns:
            Bytes representation of the Write Single Coil PDU

        """
        coil_value = 0xFF00 if self.value else 0x0000
        return struct.pack(">BHH", self.function_code, self.address, coil_value)

    def decode_response(self, response: bytes) -> bool:
        """Decode the response PDU.

        Args:
            response: Response PDU bytes

        Raises:
            InvalidResponseError: If response format is invalid

        """
        if response != self.encode_request():
            msg = "Expected response to match request"
            raise InvalidResponseError(msg, response_bytes=response)
        return self.value

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode Write Single Coil Request PDU.

        Args:
            request: the request bytes.

        Returns:
            WriteSingleCoilPDU: The decoded Write Single Coil Request PDU.

        """
        try:
            function_code, address, coil_value = struct.unpack(">BHH", request)
        except struct.error as e:
            msg = "Expected request to start with function code, address, and value"
            raise InvalidRequestError(msg, request_bytes=request) from e

        if function_code != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {function_code:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        if coil_value not in (0x0000, 0xFF00):
            msg = f"Invalid coil value: {coil_value:#06x}"
            raise InvalidRequestError(msg, request_bytes=request)

        return cls(address, coil_value == 0xFF00)

    def encode_response(self, value: bool) -> bytes:  # noqa: FBT001
        """Encode the response PDU.

        Returns:
            Bytes representation of the Write Single Coil response PDU.

        Notes:
            For Write Single Coil, the response echoes the request.

        """
        coil_value = 0xFF00 if value else 0x0000
        return struct.pack(">BHH", self.function_code, self.address, coil_value)


class WriteMultipleCoilsPDU(BasePDU[int]):
    """Write Multiple Coils PDU."""

    function_code = FunctionCode.WRITE_MULTIPLE_COILS
    rtu_response_data_length = 4  # address (2) + quantity (2)

    def __init__(self, start_address: int, values: list[bool]) -> None:
        """Initialize Write Multiple Coils PDU.

        Args:
            start_address: Starting address of the coils to write
            values: List of boolean values representing the coil states

        Raises:
            ValueError: If start_address or values are invalid

        """
        if not (0 <= start_address < 65536):
            msg = "Address must be between 0 and 65535."
            raise ValueError(msg)

        self.address = start_address
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

    def decode_response(self, response: bytes) -> int:
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
            raise InvalidResponseError(msg, response_bytes=response)

        return len(self.values)

    @classmethod
    def decode_request(cls, request: bytes) -> Self:
        """Decode Write Multiple Coils Request PDU.

        Args:
            request: the request bytes.

        Returns:
            WriteMultipleCoilsPDU: The decoded Write Multiple Coils Request PDU.

        """
        # Expected format: FC (1) + start address (2) + quantity (2) + byte count (1) + data (N)
        if len(request) < 6:
            msg = "Request too short for Write Multiple Coils"
            raise InvalidRequestError(msg, request_bytes=request)

        function_code, start_address, quantity, byte_count = struct.unpack(">BHHB", request[:6])

        if function_code != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {function_code:#04x}"
            raise InvalidRequestError(msg, request_bytes=request)

        if not (1 <= quantity <= 0x07B0):
            msg = "Number of coils must be between 1 and 1968."
            raise InvalidRequestError(msg, request_bytes=request)

        expected_len = 6 + byte_count
        if len(request) != expected_len:
            msg = f"Invalid request length: expected {expected_len}, got {len(request)}"
            raise InvalidRequestError(msg, request_bytes=request)

        expected_byte_count = (quantity + 7) // 8
        if byte_count != expected_byte_count:
            msg = f"Invalid byte count: expected {expected_byte_count}, got {byte_count}"
            raise InvalidRequestError(msg, request_bytes=request)

        data = request[6:]
        values: list[bool] = []
        for byte in data:
            values.extend([(byte >> bit) & 1 == 1 for bit in range(8)])

        return cls(start_address, values[:quantity])

    def encode_response(self, value: int) -> bytes:
        """Encode the response PDU.

        Args:
            value: The number of coils written to.

        Returns:
            Bytes representation of the Write Multiple Coils response PDU.

        """
        return struct.pack(
            ">BHH",
            self.function_code,
            self.address,
            value,
        )
