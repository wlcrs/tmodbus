r"""Word order and byte order aware struct for Modbus multi-register values.

In Modbus, the byte order within a register (which is 2 bytes long) is typically big-endian.

However, the Modbus standard did not define how values spanning multiple registers should be ordered.
This is called "word order" and can be either "big" (most significant register first) or "little"
(least significant register first).

Additionally, for values spanning 4 or more bytes, devices may use different byte orderings.
The combination of word_order and byte_order parameters determines the final byte ordering:

Byte Order Combinations (for a 32-bit value 0x0A0B0C0D):
    - word_order="big",   byte_order="big":    ABCD order → 0x0A 0x0B 0x0C 0x0D (standard Modbus)
    - word_order="big",   byte_order="little": BADC order → 0x0B 0x0A 0x0D 0x0C (byte-swapped)
    - word_order="little", byte_order="big":   CDAB order → 0x0C 0x0D 0x0A 0x0B (word-swapped)
    - word_order="little", byte_order="little": DCBA order → 0x0D 0x0C 0x0B 0x0A (full little-endian)

Note: For single-register values (16-bit), only the byte_order parameter affects the result.
      The word_order parameter only applies to multi-register values (32-bit and above).

This module provides a struct-like class that is aware of both word order and byte order when
packing and unpacking.

It extends the standard library's struct.Struct class and adds word_order and byte_order
parameters to the constructor.

Example:
    >>> from tmodbus.utils.order_aware_struct import OrderAwareStruct
    >>> # CDAB order (little-endian word order, big-endian byte order)
    >>> s = OrderAwareStruct(">I", word_order="little", byte_order="big")
    >>> data = s.pack(0x0A0B0C0D)
    >>> data
    b'\x0c\x0d\x0a\x0b'  # registers are swapped, bytes within each register are not
    >>> result = s.unpack(data)
    >>> hex(result[0])
    '0x0a0b0c0d'
    >>> # DCBA order (full little-endian)
    >>> s2 = OrderAwareStruct(">I", word_order="little", byte_order="little")
    >>> data2 = s2.pack(0x0A0B0C0D)
    >>> data2
    b'\x0d\x0c\x0b\x0a'  # all bytes reversed
    >>> # BADC order (big-endian word order, little-endian byte order)
    >>> s3 = OrderAwareStruct(">I", word_order="big", byte_order="little")
    >>> data3 = s3.pack(0x0A0B0C0D)
    >>> data3
    b'\x0b\x0a\x0d\x0c'  # bytes swapped within each register

"""

import re
import struct
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer, WriteableBuffer

BYTES_PER_REGISTER = 2


class OrderAwareStruct(struct.Struct):
    """Struct with word order and byte order awareness for multi-register values."""

    _value_lengths: list[int] | None = None
    word_order: Literal["big", "little"]
    byte_order: Literal["big", "little"]

    def __init__(
        self,
        format: str,  # noqa: A002
        word_order: Literal["big", "little"] = "big",
        byte_order: Literal["big", "little"] = "big",
    ) -> None:
        """Initialize the struct.

        The combination of word_order and byte_order determines the final byte ordering:

        Byte Order Combinations (for a 32-bit value 0x0A0B0C0D):
            - word_order="big",   byte_order="big":    ABCD → 0x0A 0x0B 0x0C 0x0D (standard Modbus)
            - word_order="big",   byte_order="little": BADC → 0x0B 0x0A 0x0D 0x0C (byte-swapped)
            - word_order="little", byte_order="big":   CDAB → 0x0C 0x0D 0x0A 0x0B (word-swapped)
            - word_order="little", byte_order="little": DCBA → 0x0D 0x0C 0x0B 0x0A (full little-endian)

        Args:
            format: Struct format string.
            word_order: Word order for multi-register values ('big' or 'little').
                - 'big': Most significant register first (standard Modbus)
                - 'little': Least significant register first
            byte_order: Byte order within each register ('big' or 'little').
                - 'big': Most significant byte first within each register (standard Modbus)
                - 'little': Least significant byte first within each register

        """
        super().__init__(format)

        if self.size % 2 != 0:
            msg = "Struct size must be a multiple of 2 bytes: Modbus holding registers are two bytes a piece."
            raise ValueError(msg)

        self.word_order = word_order
        self.byte_order = byte_order

        # Parse value lengths if we need to do any byte reordering
        # Only need transformation if not standard ABCD (word_order="big", byte_order="big")
        if word_order != "big" or byte_order != "big":
            self._value_lengths = OrderAwareStruct.parse_format_lengths(format)

    @staticmethod
    def parse_format_lengths(format_str: str) -> list[int]:
        """Parse a struct format string and return a list of value lengths in bytes."""
        # Remove byte order character if present
        if format_str and format_str[0] in "@=<>!":
            format_str = format_str[1:]

        # Regex to match format tokens (e.g., '2H', 'f', '10s')
        token_re = re.compile(r"(\d*)([xcbB?hHiIlLqQnNefdspP])")
        lengths = []
        for count_str, code in token_re.findall(format_str):
            count = int(count_str) if count_str else 1
            if code in ("s", "p"):
                # 's' and 'p' are special cases: their count indicates the total size in bytes
                lengths.append(count)
            else:
                size = struct.calcsize(code)
                lengths.extend([size] * count)

        return lengths

    def _swap_word_order(self, data: "ReadableBuffer") -> bytes:
        """Swap the word/byte order of the data based on word_order and byte_order settings."""
        if not self._value_lengths:
            # ABCD byte order (standard), no need to swap
            return bytes(data)

        # Apply byte order transformations
        start_idx = 0
        swapped_data = bytearray(data)

        current_length = 0

        for length in self._value_lengths:
            current_length += length
            if current_length % 2 != 0:
                # we need an even number of bytes to swap registers
                continue

            if current_length == BYTES_PER_REGISTER:
                # nothing to swap for single-register values
                start_idx += length
                current_length = 0
                continue

            # Apply byte order transformation for multi-register values
            swapped_data[start_idx : start_idx + current_length] = self._apply_byte_order(
                swapped_data[start_idx : start_idx + current_length],
                word_order=self.word_order,
                byte_order=self.byte_order,
            )

            start_idx += current_length
            current_length = 0

        return bytes(swapped_data)

    @staticmethod
    def _apply_byte_order(
        data: "ReadableBuffer",
        word_order: Literal["big", "little"],
        byte_order: Literal["big", "little"],
    ) -> bytes:
        """Apply byte order transformation to data based on word_order and byte_order.

        Args:
            data: Input data bytes (must be 4 or more bytes)
            word_order: Word order ('big' or 'little')
            byte_order: Byte order within registers ('big' or 'little')

        Returns:
            Transformed bytes according to word_order and byte_order combination

        """
        data_bytes = bytes(data)
        length = len(data_bytes)

        # Determine the ABCD variant based on word_order and byte_order
        if word_order == "big" and byte_order == "big":
            # ABCD: Big-endian (no change)
            return data_bytes

        if word_order == "big" and byte_order == "little":
            # BADC: Swap bytes within each 16-bit register
            result = bytearray(length)
            for i in range(0, length, 2):
                result[i] = data_bytes[i + 1]
                result[i + 1] = data_bytes[i]
            return bytes(result)

        if word_order == "little" and byte_order == "big":
            # CDAB: Swap 16-bit register order (little-endian word order)
            result = bytearray(length)
            for i in range(0, length, 2):
                src_idx = i
                dst_idx = length - i - 2
                result[dst_idx : dst_idx + 2] = data_bytes[src_idx : src_idx + 2]
            return bytes(result)

        if word_order == "little" and byte_order == "little":
            # DCBA: Full little-endian (reverse all bytes)
            return bytes(reversed(data_bytes))

        msg = f"Unknown combination: word_order={word_order}, byte_order={byte_order}"
        raise ValueError(msg)

    def unpack(self, buffer: "ReadableBuffer") -> tuple[Any, ...]:
        """Unpack buffer with word order consideration."""
        return super().unpack(self._swap_word_order(buffer))

    def unpack_from(self, buffer: "ReadableBuffer", offset: int = 0) -> tuple[Any, ...]:
        """Unpack from buffer with word order consideration."""
        return super().unpack_from(self._swap_word_order(buffer), offset)

    def pack(self, *args: Any) -> bytes:
        """Pack values into bytes with word order consideration."""
        return self._swap_word_order(super().pack(*args))

    def pack_into(self, buffer: "WriteableBuffer", offset: int, *args: Any) -> None:
        """Pack values into buffer with word order consideration."""
        packed_data = self._swap_word_order(super().pack(*args))
        buffer[offset : offset + len(packed_data)] = packed_data  # type: ignore[index]
