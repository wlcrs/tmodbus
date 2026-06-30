"""Vendor PDU example."""

import struct
from dataclasses import dataclass

from tmodbus.pdu import BaseSubFunctionClientPDU, register_pdu_class


@dataclass(frozen=True)
class LoginChallenge:
    """Login challenge response."""

    challenge: bytes  # 16 bytes


@dataclass(frozen=True)
class LoginRequestChallengePDU(BaseSubFunctionClientPDU[LoginChallenge]):
    """Modbus PDU to request a login challenge."""

    function_code = 0x41
    sub_function_code = 0x24

    def encode_request(self) -> bytes:
        """Encode LoginRequestChallengePDU."""
        data_length = 1
        value = 0
        return struct.pack(">BBBB", self.function_code, self.sub_function_code, data_length, value)

    def decode_response(self, response: bytes) -> LoginChallenge:
        """Decode LoginRequestChallengePDU response."""
        response_header_struct = struct.Struct(">BBB")
        (function_code, sub_function_code, response_content_length) = response_header_struct.unpack_from(response, 0)

        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:#04x}, received {function_code:#04x}"
            raise ValueError(msg)

        if sub_function_code != self.sub_function_code:
            msg = (
                f"Unexpected sub function code: expected {self.sub_function_code:#04x}, "
                f"received {sub_function_code:#04x}"
            )
            raise ValueError(msg)

        inverter_challenge_length = 16
        # The content length byte counts the bytes that follow it, which is the
        # challenge itself. This is also what the default sub-function RTU framing
        # (1 sub-function byte + 1 length byte + length) relies on.
        if response_content_length != inverter_challenge_length:
            msg = (
                f"Invalid response content length: expected {inverter_challenge_length}, "
                f"received {response_content_length}"
            )
            raise ValueError(msg)

        return LoginChallenge(
            challenge=response[response_header_struct.size : response_header_struct.size + inverter_challenge_length]
        )


register_pdu_class(LoginRequestChallengePDU)
