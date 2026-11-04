from collections.abc import Sequence

from teralibs.tsf.base.nops import ARCH_X64, ARCH_X86, Nops


class TerasploitModule(Nops):
    """x86 / x64 single-byte NOP sled using ``\\x90``."""

    NAME: str = "x86 Single Byte"
    DESCRIPTION: str = "Generates a NOP sled using the single-byte 0x90 (XCHG EAX, EAX) opcode. Fails cleanly when 0x90 is a bad character."
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = []

    #: Valid on both IA-32 and AMD64 - 0x90 is a legal single-byte NOP
    #: in both ISAs.
    ARCH: Sequence = [ARCH_X86, ARCH_X64]

    #: The canonical x86 NOP opcode: XCHG EAX, EAX.
    NOP_BYTE: bytes = b"\x90"
    NOP_INT: int = 0x90

    #: XCHG EAX, EAX has no register side-effects.
    SAVE_REGISTERS: Sequence = []

    def can_avoid(self, badchars: frozenset[int]) -> bool:
        """
        Return False immediately when 0x90 is a bad byte.

        Unlike polymorphic sleds this module has no alternative encoding,
        so advertising avoidance capability it does not have would cause
        the caller to waste time trying.
        """
        return self.NOP_INT not in badchars

    def generate_sled(self, size: int, badchars: frozenset[int]) -> bytes:
        """Return *size* repetitions of 0x90."""
        if self.NOP_INT in badchars:
            raise ValueError("Cannot generate x86 single-byte NOP sled: 0x90 is in the bad-character list.")

        return self.NOP_BYTE * size
