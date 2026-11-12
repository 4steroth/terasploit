from collections.abc import Mapping

from teralibs.tsf.terax.nops.base import FixedWidthNop


class X86Nop(FixedWidthNop):
    """Generate x86 NOP sequences using registered NOP strategies."""

    name = "x86"
    instruction = b"\x90"
    alignment = 1
    default_byteorder = "little"
    byteorders = ("little",)
    strategy_methods: Mapping[str, str] = {
        "single-byte": "generate_single_byte",
        "multi-byte": "generate_multi_byte",
    }
    default_strategy = "single-byte"

    # Intel/AMD-recommended NOP encodings, indexed by instruction length.
    multi_byte_instructions = (
        b"",
        b"\x90",
        b"\x66\x90",
        b"\x0f\x1f\x00",
        b"\x0f\x1f\x40\x00",
        b"\x0f\x1f\x44\x00\x00",
        b"\x66\x0f\x1f\x44\x00\x00",
        b"\x0f\x1f\x80\x00\x00\x00\x00",
        b"\x0f\x1f\x84\x00\x00\x00\x00\x00",
        b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
    )

    @classmethod
    def generate_single_byte(cls, length, badchars=(), byteorder=None):
        """Generate a sled by repeating the one-byte NOP instruction."""
        return super().generate_fixed_width(length, badchars, byteorder)

    @classmethod
    def generate_multi_byte(cls, length, badchars=(), byteorder=None):
        """Compose a sled from valid multi-byte x86 NOP instruction encodings."""
        cls._validate_length(length)
        if byteorder not in (None, "little"):
            raise ValueError(f"{cls.name} supports byte order: little")
        if length == 0:
            return b""

        forbidden = cls._normalize_badchars(badchars)
        available = [instruction for instruction in cls.multi_byte_instructions[1:] if not set(instruction) & forbidden]
        if not available:
            raise ValueError(f"no {cls.name} NOP encoding satisfies the supplied bad characters")

        # Dynamic programming avoids greedy dead ends when a byte constraint
        # removes a useful instruction length.
        sequences = [None] * (length + 1)
        sequences[0] = ()
        for size in range(1, length + 1):
            candidates = [
                sequences[size - len(instruction)] + (instruction,)
                for instruction in available
                if len(instruction) <= size and sequences[size - len(instruction)] is not None
            ]
            if candidates:
                sequences[size] = max(candidates, key=lambda sequence: tuple(map(len, sequence)))

        if sequences[length] is None:
            raise ValueError(f"cannot construct a {cls.name} NOP sled of exactly {length} bytes with the selected strategy and bad characters")
        return b"".join(sequences[length])
