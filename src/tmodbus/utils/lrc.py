"""Longitudinal Redundancy Check (LRC) Utility Functions."""


def calculate_lrc(data: bytes) -> int:
    """Use to compute the longitudinal redundancy check against a string."""
    # The LRC is the two's complement of the 8-bit sum of all bytes. Letting the
    # C-level sum() add everything up first is a lot faster than a Python loop.
    return (-sum(data)) & 0xFF


def validate_lrc(data: bytes, check: int) -> bool:
    """Check if the passed in data matches the LRC."""
    return calculate_lrc(data) == check
