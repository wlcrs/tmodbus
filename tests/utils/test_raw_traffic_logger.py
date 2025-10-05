"""Tests for tmodbus/utils/raw_traffic_logger.py ."""

from typing import Any
from unittest.mock import patch

from tmodbus.utils.raw_traffic_logger import _format_bytes, log_raw_traffic


class _DummyLogger:
    def __init__(self) -> None:
        self.records: list[tuple[Any, dict[str, Any]]] = []

    def debug(self, *args: Any, **kwargs: Any) -> None:
        self.records.append((args, kwargs))


def test_format_bytes() -> None:
    """Test formatting of bytes to hex string."""
    assert _format_bytes(b"\x01\x02\xab") == "01 02 AB"
    assert _format_bytes(b"") == ""
    assert _format_bytes(b"\x00\xff") == "00 FF"


def test_log_raw_traffic_sent() -> None:
    """Test logging of sent traffic."""
    dummy = _DummyLogger()
    with patch("tmodbus.utils.raw_traffic_logger.raw_traffic_logger", dummy):
        log_raw_traffic("rtu", "sent", b"\x01\x02")

    args, _kwargs = dummy.records[-1]
    assert args[0] == "%6s %s: %s %s"
    assert args[1] == "rtu"
    assert args[2] == "sent"
    assert args[3] == "01 02"
    assert args[4] == ""


def test_log_raw_traffic_recv_error() -> None:
    """Test logging of received error traffic."""
    dummy = _DummyLogger()
    with patch("tmodbus.utils.raw_traffic_logger.raw_traffic_logger", dummy):
        log_raw_traffic("tcp", "recv", b"\xff", is_error=True)
    args, _kwargs = dummy.records[-1]
    assert args[1] == "tcp"
    assert args[2] == "recv"
    assert args[3] == "FF"
    assert args[4] == "[!]"
