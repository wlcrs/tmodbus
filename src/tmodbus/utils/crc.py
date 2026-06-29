"""ModbusLink CRC16 Checksum Utility Module.

Provides CRC16 checksum functionality required by Modbus RTU protocol.

Uses polynomial 0xA001 (reverse of 0x8005).
"""


def _build_crc16_table() -> tuple[int, ...]:
    """Precompute the CRC16 lookup table for polynomial 0xA001.

    Each entry holds the CRC contribution of a single input byte, so the main
    loop can process a byte at a time instead of bit by bit.
    """
    table = []
    for byte in range(256):
        crc = byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 0x0001 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC16_TABLE = _build_crc16_table()


def calculate_crc16(data: bytes) -> bytes:
    r"""Calculate CRC16 Checksum.

    Args:
        data: Data frame for checksum calculation (address+PDU)

    Returns: 2-byte CRC checksum (little-endian bytes)

    Example:
        >>> data = b'\x01\x03\x00\x00\x00\x01'
        >>> crc = calculate_crc16(data)
        >>> crc.hex()
        '840a'

    """
    crc = 0xFFFF  # Initial value is 0xFFFF

    for byte in data:
        # Table-driven: fold one byte at a time using the precomputed table.
        crc = (crc >> 8) ^ _CRC16_TABLE[(crc ^ byte) & 0xFF]

    # Return 2-byte CRC in little-endian format
    return crc.to_bytes(2, byteorder="little")


def validate_crc16(frame_with_crc: bytes) -> bool:
    r"""Validate Complete Data Frame with CRC.

    Args:
        frame_with_crc: Complete data frame containing CRC checksum

    Returns: True if CRC verification is correct, False otherwise

    Example:
        >>> frame = b'\x01\x03\x00\x00\x00\x01\x84\x0a'
        >>> validate_crc16(frame)
        True

    """
    if len(frame_with_crc) < 3:  #  At least 1 byte data + 2 bytes CRC required
        return False

    #  Separate data and CRC
    data, received_crc = frame_with_crc[:-2], frame_with_crc[-2:]

    # Calculate expected CRC
    expected_crc = calculate_crc16(data)

    # Compare CRC
    return received_crc == expected_crc
