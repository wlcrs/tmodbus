"""Tests for server base utilities and classes."""

from unittest.mock import patch

import pytest
from tmodbus.exceptions import InvalidRequestError
from tmodbus.pdu import (
    BaseClientPDU,
    ReadHoldingRegistersPDU,
)
from tmodbus.pdu.base import BaseSubFunctionPDU
from tmodbus.server.base import (
    AsyncBaseServer,
    get_server_pdu_class,
    get_server_pdu_class_from_buffer,
)


class DummyClientOnlyPDU(BaseClientPDU[None]):
    """A client-only PDU that does not inherit from BasePDU (not a server PDU)."""

    function_code = 0x99


class DummySubFunctionServerPDU(BaseSubFunctionPDU[None]):
    """A server-capable sub-function PDU class for testing."""

    function_code = 0x2B
    sub_function_code = 0x0E


def test_get_server_pdu_class_success() -> None:
    """Test get_server_pdu_class maps standard and sub-function codes correctly."""
    # Standard function code
    cls = get_server_pdu_class(b"\x03\x00\x00\x00\x02")
    assert cls is ReadHoldingRegistersPDU

    # Sub-function code
    with patch("tmodbus.server.base.get_subfunction_pdu_class", return_value=DummySubFunctionServerPDU):
        cls = get_server_pdu_class(b"\x2b\x0e\x01\x00")
        assert cls is DummySubFunctionServerPDU


def test_get_server_pdu_class_empty() -> None:
    """Test get_server_pdu_class raises InvalidRequestError for empty request bytes."""
    with pytest.raises(InvalidRequestError, match="Empty PDU"):
        get_server_pdu_class(b"")


def test_get_server_pdu_class_missing_subfunction() -> None:
    """Test get_server_pdu_class raises InvalidRequestError for truncated sub-function codes."""
    with pytest.raises(InvalidRequestError, match="Missing sub-function code"):
        get_server_pdu_class(b"\x2b")


def test_get_server_pdu_class_non_server() -> None:
    """Test get_server_pdu_class raises ValueError for client-only PDUs."""
    with (
        pytest.raises(ValueError, match="does not implement server methods"),
        patch("tmodbus.server.base.get_pdu_class", return_value=DummyClientOnlyPDU),
    ):
        get_server_pdu_class(b"\x99\x00\x00")


def test_get_server_pdu_class_from_buffer_success() -> None:
    """Test get_server_pdu_class_from_buffer resolves classes from partial stream buffers."""
    # Standard function code (buffer contains unit_id, fc, data...)
    cls = get_server_pdu_class_from_buffer(bytearray(b"\x01\x03\x00\x00\x00\x02"))
    assert cls is ReadHoldingRegistersPDU

    # Sub-function code
    with patch("tmodbus.server.base.get_subfunction_pdu_class", return_value=DummySubFunctionServerPDU):
        cls = get_server_pdu_class_from_buffer(bytearray(b"\x01\x2b\x0e\x01\x00"))
        assert cls is DummySubFunctionServerPDU


def test_get_server_pdu_class_from_buffer_missing_subfunction() -> None:
    """Test get_server_pdu_class_from_buffer returns None when sub-function code is missing."""
    # Buffer has unit_id, fc, but is missing the sub-function byte at index 2
    cls = get_server_pdu_class_from_buffer(bytearray(b"\x01\x2b"))
    assert cls is None


def test_get_server_pdu_class_from_buffer_too_short() -> None:
    """Test get_server_pdu_class_from_buffer returns None when buffer is too short to even contain function code."""
    cls = get_server_pdu_class_from_buffer(bytearray(b"\x01"))
    assert cls is None


def test_get_server_pdu_class_from_buffer_non_server() -> None:
    """Test get_server_pdu_class_from_buffer raises ValueError for client-only PDUs."""
    with (
        pytest.raises(ValueError, match="does not implement server methods"),
        patch("tmodbus.server.base.get_pdu_class", return_value=DummyClientOnlyPDU),
    ):
        get_server_pdu_class_from_buffer(bytearray(b"\x01\x99\x00"))


def test_async_base_server_abc() -> None:
    """Test AsyncBaseServer is an ABC and cannot be instantiated directly."""
    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        AsyncBaseServer()  # type: ignore[abstract]

    class IncompleteServer(AsyncBaseServer):
        pass

    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        IncompleteServer()  # type: ignore[abstract]
