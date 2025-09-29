"""Read Device Identification PDU.

cfr. section 6.21 of the Modbus Application Protocol Specification V1.1b3
"""

import logging
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Literal

from tmodbus.const import FunctionCode

from .base import BaseSubFunctionClientPDU

logger = logging.getLogger(__name__)


class ObjectName(IntEnum):
    """Object ID to Object Name mapping."""

    VENDOR_NAME = 0x00  # Basic, Mandatory
    PRODUCT_CODE = 0x01  # Basic, Mandatory
    MAJOR_MINOR_REVISION = 0x02  # Basic, Mandatory
    VENDOR_URL = 0x03  # Regular, Optional
    PRODUCT_NAME = 0x04  # Regular, Optional
    MODEL_NAME = 0x05  # Regular, Optional
    USER_APPLICATION_NAME = 0x06  # Regular, Optional

    # 0x07 to 0x7F: Reserved for regular, optional objects
    # 0x80 to 0xFF: Reserved for extended (manufacturer-specific), optional objects


class ConformityLevel(IntEnum):
    """Conformity Level."""

    BASIC = 0x01
    """Basic identification (stream access only)"""
    REGULAR = 0x02
    """Regular identification (stream access only)"""
    EXTENDED = 0x03
    """Extended identification (stream access only)"""
    BASIC_PLUS = 0x81
    """Basic identification (stream access and individual access)"""
    REGULAR_PLUS = 0x82
    """Regular identification (stream access and individual access)"""
    EXTENDED_PLUS = 0x83
    """Extended identification (stream access and individual access)"""


@dataclass(frozen=True)
class ReadDeviceIdentificationResponse:
    """Contents of the ReadDeviceInfo response."""

    device_id_code: Literal[0x01, 0x02, 0x03, 0x04]
    conformity_level: ConformityLevel
    more: bool
    next_object_id: int
    number_of_objects: int

    objects: dict[int, bytes]


class ReadDeviceIdentificationPDU(BaseSubFunctionClientPDU[ReadDeviceIdentificationResponse]):
    """Modbus Request to read a device identifier."""

    function_code = FunctionCode.ENCAPSULATED_INTERFACE_TRANSPORT

    sub_function_code = 0x0E
    read_device_id_code: Literal[0x01, 0x02, 0x03, 0x04]
    object_id: int

    def __init__(self, read_device_id_code: Literal[0x01, 0x02, 0x03, 0x04], object_id: int) -> None:
        """Create ReadDeviceIdentificationPDU."""
        self.read_device_id_code = read_device_id_code

        if not (0x00 <= object_id < 0xFF):
            msg = "Object ID must be between 0x00 and 0xFF."
            raise ValueError(msg)
        self.object_id = object_id

    def encode_request(self) -> bytes:
        """Encode ReadDeviceIdentifierPDU."""
        return struct.pack(
            ">BBBB",
            self.function_code,
            self.sub_function_code,
            self.read_device_id_code,
            self.object_id,
        )

    def decode_response(self, response: bytes) -> ReadDeviceIdentificationResponse:
        """Decode Device Identifier PDU response."""
        response_header_struct = struct.Struct(">BBBBBBB")
        (
            function_code,
            sub_function_code,
            device_id_code,
            conformity_level,
            more,
            next_object_id,
            number_of_objects,
        ) = response_header_struct.unpack_from(response, 0)

        if function_code != self.function_code:
            msg = f"Invalid function code: expected {self.function_code:02x}, received {function_code:02x}"
            raise ValueError(msg)

        if sub_function_code != self.sub_function_code:
            msg = f"Invalid sub function code: expected {self.sub_function_code:02x}, received {sub_function_code:02x}"
            raise ValueError(msg)

        if more not in (0x00, 0xFF):
            msg = f"Invalid 'more' value: {more:02x}"
            raise ValueError(msg)

        objects: dict[int, bytes] = {}
        offset = response_header_struct.size
        while offset < len(response):
            obj_id, obj_length = struct.unpack_from(">BB", response, offset)
            offset += 2
            objects[obj_id] = response[offset : offset + obj_length]
            offset += obj_length

        if offset != len(response):
            logger.warning("Response has %d extra bytes", len(response) - offset)

        return ReadDeviceIdentificationResponse(
            device_id_code=device_id_code,
            conformity_level=ConformityLevel(conformity_level),
            more=bool(more),
            next_object_id=next_object_id,
            number_of_objects=number_of_objects,
            objects=objects,
        )
