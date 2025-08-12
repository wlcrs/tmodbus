"""Raw traffic logger."""

from logging import getLogger
from typing import Literal

raw_traffic_logger = getLogger("tmodbus.raw_traffic")


def log_raw_traffic(
    transport_name: str,
    direction: Literal["sent", "recv"],
    data: bytes,
    *,
    is_error: bool = False,
) -> None:
    """Log raw Modbus TCP traffic."""
    formatted_data = _format_bytes(data)
    raw_traffic_logger.debug(
        "%6s %s: %s %s",
        transport_name,
        direction,
        formatted_data,
        "[!]" if is_error else "",
    )


def _format_bytes(data: bytes) -> str:
    """Format bytes for logging."""
    return data.hex(" ").upper()
