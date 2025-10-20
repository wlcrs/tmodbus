"""Tests for tmodbus/pdu/pdu.py ."""

import pytest
from tmodbus.const import FunctionCode
from tmodbus.pdu import (
    BaseClientPDU,
    BaseSubFunctionClientPDU,
    get_pdu_class,
    get_subfunction_pdu_class,
    register_pdu_class,
)


class TestGetPDUClass:
    """Tests for get_pdu_class function."""

    def test_get_pdu_class_valid_function_code(self) -> None:
        """Test getting PDU class by valid function code."""
        pdu_class = get_pdu_class(FunctionCode.READ_HOLDING_REGISTERS)
        assert pdu_class.__name__ == "ReadHoldingRegistersPDU"

    def test_get_pdu_class_valid_function_code_as_int(self) -> None:
        """Test getting PDU class by function code as int."""
        pdu_class = get_pdu_class(0x03)  # FunctionCode.READ_HOLDING_REGISTERS
        assert pdu_class.__name__ == "ReadHoldingRegistersPDU"

    def test_get_pdu_class_unknown_function_code(self) -> None:
        """Test unknown function code raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported function code: 0x99"):
            get_pdu_class(0x99)

    def test_get_pdu_class_with_sub_function(self) -> None:
        """Test getting PDU class with sub-function code."""
        # ReadDeviceIdentificationPDU uses function code 0x2B and sub-function code 0x0E
        pdu_class = get_subfunction_pdu_class(0x2B, 0x0E)
        assert pdu_class.__name__ == "ReadDeviceIdentificationPDU"

    def test_get_pdu_class_unknown_sub_function_code(self) -> None:
        """Test unknown sub-function code raises ValueError."""
        # Function code 0x2B is valid, but sub-function 0xFF is not registered
        with pytest.raises(
            ValueError,
            match="Unsupported sub-function code: 0xff for function code 0x2b",
        ):
            get_subfunction_pdu_class(0x2B, 0xFF)


class TestRegisterPDUClass:
    """Tests for register_pdu_class function."""

    def test_register_normal_pdu_class(self) -> None:
        """Test registering a normal PDU class."""

        class CustomPDU(BaseClientPDU[int]):
            function_code = 0xF0

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # Register the custom PDU
        register_pdu_class(CustomPDU)

        # Verify it can be retrieved
        pdu_class = get_pdu_class(0xF0)
        assert pdu_class == CustomPDU

    def test_register_duplicate_normal_pdu_class(self) -> None:
        """Test registering a duplicate function code raises ValueError."""

        class CustomPDU1(BaseClientPDU[int]):
            function_code = 0xF1

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        class CustomPDU2(BaseClientPDU[int]):
            function_code = 0xF1

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # Register first PDU
        register_pdu_class(CustomPDU1)

        # Try to register duplicate
        with pytest.raises(
            ValueError,
            match=r"Function code 0xf1 is already registered to CustomPDU1",
        ):
            register_pdu_class(CustomPDU2)

    def test_register_sub_function_pdu_class(self) -> None:
        """Test registering a sub-function PDU class."""

        class CustomSubFunctionPDU(BaseSubFunctionClientPDU[int]):
            function_code = 0xF2
            sub_function_code = 0x01

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # Register the custom sub-function PDU
        register_pdu_class(CustomSubFunctionPDU)

        # Verify it can be retrieved
        pdu_class = get_subfunction_pdu_class(0xF2, 0x01)
        assert pdu_class == CustomSubFunctionPDU

    def test_register_duplicate_sub_function_pdu_class(self) -> None:
        """Test registering a duplicate sub-function code raises ValueError."""

        class CustomSubFunctionPDU1(BaseSubFunctionClientPDU[int]):
            function_code = 0xF3
            sub_function_code = 0x01

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        class CustomSubFunctionPDU2(BaseSubFunctionClientPDU[int]):
            function_code = 0xF3
            sub_function_code = 0x01

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # Register first sub-function PDU
        register_pdu_class(CustomSubFunctionPDU1)

        # Try to register duplicate
        with pytest.raises(
            ValueError,
            match=(
                r"A PDU with function code 0xf3, "
                r"and sub-function code 0x01 is already registered: "
                r"CustomSubFunctionPDU1\."
            ),
        ):
            register_pdu_class(CustomSubFunctionPDU2)

    def test_register_sub_function_pdu_when_normal_exists(self) -> None:
        """Test registering a sub-function PDU when a normal PDU already exists."""

        class NormalPDU(BaseClientPDU[int]):
            function_code = 0xF4

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        class SubFunctionPDU(BaseSubFunctionClientPDU[int]):
            function_code = 0xF4
            sub_function_code = 0x01

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # Register normal PDU first
        register_pdu_class(NormalPDU)

        # Try to register sub-function PDU with same function code
        with pytest.raises(
            ValueError,
            match=(
                r"Function code 0xf4 is already registered "
                r"for a non-subfunction PDU NormalPDU\."
            ),
        ):
            register_pdu_class(SubFunctionPDU)

    def test_register_normal_pdu_when_sub_function_exists(self) -> None:
        """Test registering a normal PDU when sub-function PDUs already exist."""

        class SubFunctionPDU1(BaseSubFunctionClientPDU[int]):
            function_code = 0xF5
            sub_function_code = 0x01

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        class SubFunctionPDU2(BaseSubFunctionClientPDU[int]):
            function_code = 0xF5
            sub_function_code = 0x02

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        class NormalPDU(BaseClientPDU[int]):
            function_code = 0xF5

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # Register sub-function PDUs first
        register_pdu_class(SubFunctionPDU1)
        register_pdu_class(SubFunctionPDU2)

        # Try to register normal PDU with same function code
        with pytest.raises(
            ValueError,
            match=(
                r"Function code 0xf5 is already registered with sub-functions: "
                r"0x01: SubFunctionPDU1, 0x02: SubFunctionPDU2"
            ),
        ):
            register_pdu_class(NormalPDU)

    def test_register_multiple_sub_functions_same_function_code(self) -> None:
        """Test registering multiple sub-function PDUs with the same function code."""

        class SubFunctionPDUA(BaseSubFunctionClientPDU[int]):
            function_code = 0xF6
            sub_function_code = 0x01

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        class SubFunctionPDUB(BaseSubFunctionClientPDU[int]):
            function_code = 0xF6
            sub_function_code = 0x02

            def encode_request(self) -> bytes:
                return b""

            def decode_response(self, _response: bytes) -> int:
                return 0

        # Register both sub-function PDUs
        register_pdu_class(SubFunctionPDUA)
        register_pdu_class(SubFunctionPDUB)

        # Verify both can be retrieved
        pdu_class_a = get_subfunction_pdu_class(0xF6, 0x01)
        pdu_class_b = get_subfunction_pdu_class(0xF6, 0x02)
        assert pdu_class_a == SubFunctionPDUA
        assert pdu_class_b == SubFunctionPDUB
