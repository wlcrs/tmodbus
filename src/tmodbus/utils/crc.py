"""ModbusLink CRC16 Checksum Utility Module.

Provides CRC16 checksum functionality required by Modbus RTU protocol.

Uses polynomial 0xA001 (reverse of 0x8005).
"""


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
    crc = 0xFFFF  #  Initial value is 0xFFFF

    for byte in data:
        crc ^= byte  #  XOR operation
        for _ in range(8):  #  Process 8 bits
            if crc & 0x0001:  #  Check lowest bit
                crc >>= 1  #  Right shift by one bit
                crc ^= 0xA001  #  XOR with polynomial
            else:
                crc >>= 1  #  Right shift by one bit

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
