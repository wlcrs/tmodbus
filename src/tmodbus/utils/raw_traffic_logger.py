"""Raw traffic logger."""

from logging import getLogger

raw_traffic_logger = getLogger("tmodbus.raw_traffic")


def _format_bytes(data: bytes) -> str:
    """Format bytes for logging."""
    return data.hex(" ").upper()

