"""Tests for tmodbus/pdu/base.py ."""

import pytest
from tmodbus.exceptions import InvalidRequestError, InvalidResponseError
from tmodbus.pdu.base import (
    BaseClientPDU,
    BasePDU,
    BaseSubFunctionClientPDU,
    BaseSubFunctionPDU,
)


class TestBaseClientPDU:
    """Tests for BaseClientPDU."""

    def test_get_expected_response_data_length_with_fixed_length(self) -> None:
        """Test get_expected_response_data_length with rtu_response_data_length set."""

        class TestPDU(BaseClientPDU[int]):
            function_code = 0x01
            rtu_response_data_length = 10

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        assert TestPDU.get_expected_response_data_length(b"") == 10

    def test_get_expected_response_data_length_from_first_byte(self) -> None:
        """Test get_expected_response_data_length when length is in first byte."""

        class TestPDU(BaseClientPDU[int]):
            function_code = 0x01

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # First byte is 0x0f (15), so expected length is 1 + 15 = 16
        assert TestPDU.get_expected_response_data_length(b"\x0f") == 16
        # First byte is 0x05 (5), so expected length is 1 + 5 = 6
        assert TestPDU.get_expected_response_data_length(b"\x05") == 6


class TestBasePDU:
    """Tests for BasePDU."""

    def test_get_expected_response_data_length_with_fixed_length(self) -> None:
        """Test expected response data length for BasePDU with fixed length."""

        class TestPDU(BasePDU[int]):
            function_code = 0x01
            rtu_response_data_length = 10

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        assert TestPDU.get_expected_response_data_length(b"") == 10

    def test_get_expected_response_data_length_from_first_byte(self) -> None:
        """Test expected response data length when length is in first byte."""

        class TestPDU(BasePDU[int]):
            function_code = 0x01

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        assert TestPDU.get_expected_response_data_length(b"\x0f") == 16

    def test_get_expected_request_data_length_with_fixed_length(self) -> None:
        """Test get_expected_request_data_length with rtu_request_data_length set."""

        class TestPDU(BasePDU[int]):
            function_code = 0x01
            rtu_request_data_length = 8

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        # Should return the fixed length
        assert TestPDU.get_expected_request_data_length(b"") == 8

    def test_get_expected_request_data_length_from_first_byte(self) -> None:
        """Test get_expected_request_data_length when length is in first byte."""

        class TestPDU(BasePDU[int]):
            function_code = 0x01

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        # First byte is 0x0a (10), so expected length is 1 + 10 = 11
        assert TestPDU.get_expected_request_data_length(b"\x0a") == 11
        # First byte is 0x03 (3), so expected length is 1 + 3 = 4
        assert TestPDU.get_expected_request_data_length(b"\x03") == 4


class TestBaseSubFunctionClientPDU:
    """Tests for BaseSubFunctionClientPDU."""

    def test_get_expected_response_data_length_invalid_sub_function_code(self) -> None:
        """Test that invalid sub-function code raises InvalidResponseError."""

        class TestPDU(BaseSubFunctionClientPDU[int]):
            function_code = 0x2B
            sub_function_code = 0x0E

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # Data with wrong sub-function code (0x0F instead of 0x0E)
        with pytest.raises(InvalidResponseError) as exc_info:
            TestPDU.get_expected_response_data_length(b"\x0f\x10")

        assert "Expected sub-function code 14, got 15" in str(exc_info.value)

    def test_get_expected_response_data_length_with_fixed_length(self) -> None:
        """Test get_expected_response_data_length with rtu_response_data_length set."""

        class TestPDU(BaseSubFunctionClientPDU[int]):
            function_code = 0x2B
            sub_function_code = 0x0E
            rtu_response_data_length = 20

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # Should return the fixed length when sub-function code matches
        assert TestPDU.get_expected_response_data_length(b"\x0e\x00") == 20

    def test_get_expected_response_data_length_from_second_byte(self) -> None:
        """Test get_expected_response_data_length when length is in second byte."""

        class TestPDU(BaseSubFunctionClientPDU[int]):
            function_code = 0x2B
            sub_function_code = 0x0E

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # First byte is sub-function (0x0E), second byte is length (0x0C = 12)
        # Expected: 1 (sub-function) + 1 (length byte) + 12 = 14
        assert TestPDU.get_expected_response_data_length(b"\x0e\x0c") == 14
        # First byte is sub-function (0x0E), second byte is length (0x05 = 5)
        # Expected: 1 + 1 + 5 = 7                               # noqa: ERA001
        assert TestPDU.get_expected_response_data_length(b"\x0e\x05") == 7


class TestBaseSubFunctionPDU:
    """Tests for BaseSubFunctionPDU."""

    def test_get_expected_response_data_length_invalid_sub_function_code(self) -> None:
        """Test that invalid sub-function code raises InvalidResponseError."""

        class TestPDU(BaseSubFunctionPDU[int]):
            function_code = 0x2B
            sub_function_code = 0x0E

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        # Data with wrong sub-function code
        with pytest.raises(InvalidResponseError) as exc_info:
            TestPDU.get_expected_response_data_length(b"\x0a\x10")

        assert "Expected sub-function code 14, got 10" in str(exc_info.value)

    def test_get_expected_response_data_length_with_fixed_length(self) -> None:
        """Test get_expected_response_data_length with rtu_response_data_length set."""

        class TestPDU(BaseSubFunctionPDU[int]):
            function_code = 0x2B
            sub_function_code = 0x0E
            rtu_response_data_length = 25

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        # Should return the fixed length
        assert TestPDU.get_expected_response_data_length(b"\x0e\x00") == 25

    def test_get_expected_response_data_length_from_second_byte(self) -> None:
        """Test get_expected_response_data_length when length is in second byte."""

        class TestPDU(BaseSubFunctionPDU[int]):
            function_code = 0x2B
            sub_function_code = 0x0E

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        # Second byte contains length
        assert TestPDU.get_expected_response_data_length(b"\x0e\x08") == 10
        assert TestPDU.get_expected_response_data_length(b"\x0e\x14") == 22

    def test_get_expected_request_data_length_invalid_sub_function_code(self) -> None:
        """Test that invalid sub-function code raises InvalidRequestError."""

        class TestPDU(BaseSubFunctionPDU[int]):
            function_code = 0x2B
            sub_function_code = 0x0E

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        # Data with wrong sub-function code (0x0D instead of 0x0E)
        with pytest.raises(InvalidRequestError) as exc_info:
            TestPDU.get_expected_request_data_length(b"\x0d\x10")

        assert "Expected sub-function code 14, got 13" in str(exc_info.value)

    def test_get_expected_request_data_length_with_fixed_length(self) -> None:
        """Test get_expected_request_data_length with rtu_request_data_length set."""

        class TestPDU(BaseSubFunctionPDU[int]):
            function_code = 0x2B
            sub_function_code = 0x0E
            rtu_request_data_length = 15

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        # Should return the fixed length when sub-function code matches
        assert TestPDU.get_expected_request_data_length(b"\x0e\x00") == 15

    def test_get_expected_request_data_length_from_first_byte(self) -> None:
        """Test get_expected_request_data_length when length is in first byte."""

        class TestPDU(BaseSubFunctionPDU[int]):
            function_code = 0x2B
            sub_function_code = 0x0E

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

            @classmethod
            def decode_request(cls, _request: bytes) -> "TestPDU":
                return cls()

            def encode_response(self, _value: int) -> bytes:
                return b""

        # First byte is sub-function code (0x0E = 14)
        # Expected: 1 (length byte) + 14 = 15
        assert TestPDU.get_expected_request_data_length(b"\x0e") == 15
        # First byte is different value
        with pytest.raises(InvalidRequestError):
            TestPDU.get_expected_request_data_length(b"\x0d")
