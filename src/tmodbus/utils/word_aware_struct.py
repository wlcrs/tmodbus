r"""Word order aware struct for Modbus multi-register values.

In Modbus, the byte order within a register (which is 2 bytes long) is defined as big-endian.

However, the Modbus standard did not define how values spanning multiple registers should be ordered.
This is called "word order" and can be either "big" (most significant register first) or "little"
(least significant register first).

This module provides a struct-like class that is aware of word order when packing and unpacking.

It extends the standard library's struct.Struct class and adds a word_order parameter to the constructor.

Example:
    >>> from tmodbus.utils.word_aware_struct import WordOrderAwareStruct
    >>> s = WordOrderAwareStruct(">I", word_order="little")  # 32-bit unsigned int, little-endian word order
    >>> data = s.pack(0x0A0B0C0D)
    >>> data
    b'\x0c\x0d\x0a\x0b' # the registers are swapped, the bytes within each register are not
    >>> result = s.unpack(data)
    >>> hex(result[0])
    '0x0a0b0c0d'

"""

import re
import struct
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer, WriteableBuffer

BYTES_PER_REGISTER = 2


class WordOrderAwareStruct(struct.Struct):
    """Struct with word order awareness for multi-register values."""

    _value_lengths: list[int] | None = None

    def __init__(
        self,
        format: str,  # noqa: A002
        word_order: Literal["big", "little"] = "big",
    ) -> None:
        """Initialize the struct.

        Args:
            format: Struct format string.
            word_order: Word order for multi-register values ('big' or 'little').

        """
        super().__init__(format)

        if self.size % 2 != 0:
            msg = "Struct size must be a multiple of 2 bytes: Modbus holding registers are two bytes a piece."
            raise ValueError(msg)

        self.word_order = word_order
        if word_order == "little":
            self._value_lengths = WordOrderAwareStruct.parse_format_lengths(format)

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
        """Swap the word order of the data if needed."""
        if not self._value_lengths:
            # big endian word order, no need to swap
            return bytes(data)

        # Swap the order of 2-byte registers, but do not reverse bytes within each register
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

            registers_to_swap = length // BYTES_PER_REGISTER

            for swap_idx in range(registers_to_swap):
                src_idx = start_idx + swap_idx * BYTES_PER_REGISTER
                dst_idx = start_idx + current_length - swap_idx * BYTES_PER_REGISTER - BYTES_PER_REGISTER

                swapped_data[dst_idx : dst_idx + BYTES_PER_REGISTER] = data[src_idx : src_idx + BYTES_PER_REGISTER]  # type: ignore[index]

            start_idx += current_length
            current_length = 0

        return bytes(swapped_data)

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
