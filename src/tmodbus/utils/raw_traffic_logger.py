"""Raw traffic logger."""

from logging import DEBUG, getLogger
from typing import Literal

raw_traffic_logger = getLogger("tmodbus.raw_traffic")


def log_raw_traffic(
    transport_name: str,
    direction: Literal["sent", "recv"],
    data: bytes,
    *,
    is_error: bool = False,
    is_ignored: bool = False,
) -> None:
    """Log raw Modbus traffic when debug logging is enabled."""
    # This runs on every frame in both directions, and formatting the bytes to
    # hex is not free. Skip the work entirely when nobody is listening.
    if not raw_traffic_logger.isEnabledFor(DEBUG):
        return

    status = ""
    if is_error:
        status = "[!]"
    elif is_ignored:
        status = "[ignored]"

    raw_traffic_logger.debug(
        "%6s %s: %s %s",
        transport_name,
        direction,
        _format_bytes(data),
        status,
    )


def _format_bytes(data: bytes) -> str:
    """Format bytes for logging."""
    return data.hex(" ").upper()
