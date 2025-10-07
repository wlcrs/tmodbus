"""Longitudinal Redundancy Check (LRC) Utility Functions."""


def calculate_lrc(data: bytes) -> int:
    """Use to compute the longitudinal redundancy check against a string."""
    lrc = 0
    for byte in data:
        lrc = (lrc + byte) & 0xFF

    return ((lrc ^ 0xFF) + 1) & 0xFF


def validate_lrc(data: bytes, check: int) -> bool:
    """Check if the passed in data matches the LRC."""
    return calculate_lrc(data) == check
