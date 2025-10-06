"""PDU's that are specific to serial line communication."""

import struct
from dataclasses import dataclass
from typing import Self

from tmodbus.exceptions import InvalidRequestError, InvalidResponseError

from .base import BasePDU


@dataclass(frozen=True)
class ServerIdResponse:
    """Response data structure for Report Server ID."""

    server_id: bytes
    run_indicator_status: bool
    additional_data: bytes


ID_ON = 0xFF
ID_OFF = 0x00


class ReportServerIdPDU(BasePDU[ServerIdResponse]):
    """PDU for Report Server ID (function code 0x11)."""

    function_code = 0x11

    def __init__(self) -> None:
        """Initialize ReportServerIdPDU."""

    def encode_request(self) -> bytes:
        """Encode the PDU into bytes.

        Returns:
            Encoded bytes of the PDU.

        """
        return bytes([self.function_code])

    def decode_response(self, response: bytes) -> ServerIdResponse:
        """Decode the response PDU.

        Args:
            response: Bytes to decode.

        Returns:
            Instance of ServerIdResponse.

        Raises:
            InvalidResponseError: If the response is invalid.

        """
        # response format: function code (1 byte) + byte count (1 byte) + server ID + status (1 byte)

        # note: the protocol doesn't specify where the server ID ends and where the additional data starts
        # we can find the status byte by looking for the first occurrence of 0xFF or 0x00 after the byte count

        try:
            function_code, byte_count = struct.unpack_from(">BB", response, 0)
        except struct.error as e:
            msg = "Expected response to start with function code and byte count"
            raise InvalidResponseError(msg, response_bytes=response) from e

        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:#04x}, received {function_code:#04x}"
            raise InvalidResponseError(msg, response_bytes=response)

        if len(response) < 2 + byte_count:
            msg = f"Response length {len(response)} is less than expected {2 + byte_count}"
            raise InvalidResponseError(msg, response_bytes=response)

        # we can the data after the byte count for the status indicator byte to know
        # where the server_id ends and where the additional data starts

        for idx in range(2, 2 + byte_count):
            if response[idx] in (ID_ON, ID_OFF):
                server_id = response[2:idx]
                run_indicator_status = response[idx] == ID_ON
                additional_data = response[idx + 1 : 2 + byte_count]
                break
        else:
            msg = "Run indicator status byte not found in response"
            raise InvalidResponseError(msg, response_bytes=response)

        return ServerIdResponse(
            server_id=server_id,
            run_indicator_status=run_indicator_status,
            additional_data=additional_data,
        )

    @classmethod
    def decode_request(cls, data: bytes) -> Self:
        """Decode bytes into a PDU instance.

        Args:
            data: Bytes to decode.

        Returns:
            Instance of ReportServerIdPDU.

        Raises:
            InvalidRequestError: If the data is invalid.

        """
        if len(data) != 1:
            msg = "Expected request with only function code"
            raise InvalidRequestError(msg)

        if data[0] != cls.function_code:
            msg = f"Invalid function code: expected {cls.function_code:#04x}, received {data[0]:#04x}"
            raise InvalidRequestError(msg)
        return cls()

    def encode_response(self, value: ServerIdResponse) -> bytes:
        """Encode the response PDU.

        Args:
            value: Instance of ServerIdResponse to encode.

        Returns:
            Encoded bytes of the response PDU.

        """
        byte_count = len(value.server_id) + 1 + len(value.additional_data)  # +1 for run indicator status
        run_indicator_status = ID_ON if value.run_indicator_status else ID_OFF
        return bytes([self.function_code, byte_count, *value.server_id, run_indicator_status, *value.additional_data])
