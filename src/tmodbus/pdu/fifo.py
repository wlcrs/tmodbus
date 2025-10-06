"""Read FIFO Queue PDU Module."""

import struct
from dataclasses import dataclass
from typing import Self

from tmodbus.const import FunctionCode
from tmodbus.pdu.base import BasePDU


@dataclass(frozen=True)
class ReadFifoQueuePDU(BasePDU[list[int]]):
    """Read FIFO Queue PDU (Function Code 0x18)."""

    address: int

    function_code: int = FunctionCode.READ_FIFO_QUEUE

    def __post_init__(self) -> None:
        """Initialize Read FIFO Queue PDU.

        Args:
            address: Address of the FIFO queue to read

        """
        if not (0 <= self.address <= 0xFFFF):
            msg = f"Address {self.address} out of range (0-65535)."
            raise ValueError(msg)

    def encode_request(self) -> bytes:
        """Encode Read FIFO Queue request PDU.

        Returns:
            Encoded request PDU as bytes

        """
        return struct.pack(">BH", self.function_code, self.address)

    @classmethod
    def decode_request(cls, data: bytes) -> Self:
        """Decode Read FIFO Queue request PDU.

        Args:
            data: Request PDU data as bytes

        Returns:
            Decoded ReadFifoQueuePDU instance

        Raises:
            ValueError: If data length is incorrect

        """
        if len(data) != 3:
            msg = f"Invalid Read FIFO Queue request length: {len(data)}. Expected 3."
            raise ValueError(msg)

        function_code, address = struct.unpack(">BH", data)

        if function_code != cls.function_code:
            msg = f"Invalid function code: {function_code:#04x}. Expected {cls.function_code:#04x}."
            raise ValueError(msg)

        return cls(address=address)

    def encode_response(self, values: list[int]) -> bytes:
        """Encode Read FIFO Queue response PDU.

        Args:
            values: List of values from the FIFO queue

        Returns:
            Encoded response PDU as bytes

        Raises:
            ValueError: If count or values are out of range

        """
        if not (0 <= len(values) <= 31):
            msg = f"Count {len(values)} out of range (0-31)."
            raise ValueError(msg)

        for value in values:
            if not (0 <= value <= 0xFFFF):
                msg = f"Value {value} out of range (0-65535)."
                raise ValueError(msg)

        # Byte count = 2 bytes for FIFO count + (number of values * 2 bytes for each value)
        byte_count = 2 + (len(values) * 2)
        return struct.pack(f">BHH{'H' * len(values)}", self.function_code, byte_count, len(values), *values)

    def decode_response(self, data: bytes) -> list[int]:
        """Decode Read FIFO Queue response PDU.

        Args:
            data: Response PDU data as bytes

        Returns:
            List of values from the FIFO queue

        Raises:
            ValueError: If data length is incorrect or count doesn't match values

        """
        if len(data) < 5:
            msg = f"Invalid Read FIFO Queue response length: {len(data)}. Minimum expected is 5."
            raise ValueError(msg)

        response_header_struct = struct.Struct(">BHH")

        function_code, byte_count, fifo_count = response_header_struct.unpack_from(data, 0)

        if function_code != self.function_code:
            msg = f"Invalid function code: {function_code:#04x}. Expected {self.function_code:#04x}."
            raise ValueError(msg)

        if byte_count != len(data) - 3:
            msg = f"Byte count {byte_count} does not match actual data length {len(data) - 3}."
            raise ValueError(msg)

        values_count = (byte_count // 2) - 1
        values = list(struct.unpack(f">{values_count}H", data[response_header_struct.size :]))

        # Validate that the FIFO count matches the number of values
        if fifo_count != len(values):
            msg = f"FIFO count {fifo_count} does not match number of values {len(values)}."
            raise ValueError(msg)

        return values
