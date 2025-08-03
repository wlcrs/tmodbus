
from tmodbus.pdu import BaseModbusPDU


def test_base_modbus_pdu_expected_data_length():
    """Test expected data length for BaseModbusPDU."""

    class TestPDU(BaseModbusPDU):
        rtu_response_data_length = 10

        def encode_request(self) -> bytes:
            return b""

        def decode_response(self, response: bytes) -> None:
            pass

    assert TestPDU.get_expected_data_length(b"") == 10

    class TestPDUWithoutLength(BaseModbusPDU):
        def encode_request(self) -> bytes:
            return b""

        def decode_response(self, response: bytes) -> None:
            pass

    assert TestPDUWithoutLength.get_expected_data_length(b"\x0f") == 15
