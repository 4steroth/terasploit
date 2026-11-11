import dataclasses
from collections.abc import Sequence

from teralibs.tsf.core.module.base import Base
from teralibs.tsf.pex.arch import (
    ARCH_AARCH64,
    ARCH_ALL,
    ARCH_ARMBE,
    ARCH_ARMLE,
    ARCH_BASH,
    ARCH_CBEA,
    ARCH_CBEA64,
    ARCH_CMD,
    ARCH_JAVA,
    ARCH_LUA,
    ARCH_MIPS,
    ARCH_MIPS64,
    ARCH_MIPS64LE,
    ARCH_MIPSBE,
    ARCH_MIPSLE,
    ARCH_NODEJS,
    ARCH_PERL,
    ARCH_PHP,
    ARCH_PPC,
    ARCH_PPC64,
    ARCH_PPC64LE,
    ARCH_PPCE500V2,
    ARCH_PYTHON,
    ARCH_RUBY,
    ARCH_SPARC,
    ARCH_SPARC64,
    ARCH_TTY,
    ARCH_X64,
    ARCH_X86,
    ARCH_X86_64,
    ARCH_ZARCH,
)
from teralibs.tsf.utils.exception import NopError


# Everything in the module
__all__ = [
    # Architectures
    "ARCH_AARCH64",
    "ARCH_ALL",
    "ARCH_ARMBE",
    "ARCH_ARMLE",
    "ARCH_BASH",
    "ARCH_CBEA",
    "ARCH_CBEA64",
    "ARCH_CMD",
    "ARCH_JAVA",
    "ARCH_LUA",
    "ARCH_MIPS",
    "ARCH_MIPS64",
    "ARCH_MIPS64LE",
    "ARCH_MIPSBE",
    "ARCH_MIPSLE",
    "ARCH_NODEJS",
    "ARCH_PERL",
    "ARCH_PHP",
    "ARCH_PPC",
    "ARCH_PPC64",
    "ARCH_PPC64LE",
    "ARCH_PPCE500V2",
    "ARCH_PYTHON",
    "ARCH_RUBY",
    "ARCH_SPARC",
    "ARCH_SPARC64",
    "ARCH_TTY",
    "ARCH_X64",
    "ARCH_X86",
    "ARCH_X86_64",
    "ARCH_ZARCH",
]


@dataclasses.dataclass(slots=True)
class NopsResult:
    """Outcome of a single :meth:`Nops.generate_sled` call."""

    success: bool
    sled_bytes: bytes
    nop_name: str
    error: str = ""


class Nops(Base):
    """Base class for all Terasploit NOP sled modules."""

    #: Human-readable module name shown in the console.
    NAME: str

    #: One-paragraph description of the exploit.
    DESCRIPTION: str

    #: Author handle or contact information.
    AUTHOR: str | Sequence

    #: SPDX license identifier, e.g. "BSD-3-CLAUSE".
    LICENSE: str = "BSD-3-CLAUSE"

    #: Semantic version string, e.g. "1.0".
    VERSION: str

    #: Module reliability ranking: "low", "normal", "high",
    #: or "excellent".
    RANK: str = "normal"

    #: External references as [type, url] pairs.
    REFERENCES: Sequence

    # Target specification

    #: Target architectures. Use the ARCH_* constants from
    #: core.payload.base for consistency. Use ["all"] to accept
    #: any architecture.
    ARCH: Sequence

    #: Registers this NOP sled preserves.
    #:
    #: Encoders and exploit writers may consult this list to choose a NOP
    #: module that does not clobber a register they depend on.  Set to an
    #: empty list when the sled has no register side-effects (e.g. a pure
    #: single-byte ``\x90`` sled on x86).
    SAVE_REGISTERS: Sequence

    # Public API

    def generate(self, size: int, badchars: frozenset[int] | None = None) -> NopsResult:
        """Generate a NOP sled of *size* bytes and return a :class:`NopsResult`."""
        if badchars is None:
            badchars = frozenset()

        if size < 0:
            return NopsResult(
                success=False,
                sled_bytes=b"",
                nop_name=self.NAME,
                error=f"Requested sled size {size} is negative.",
            )

        try:
            sled = self.generate_sled(size, badchars)

        except NopError as exc:
            return NopsResult(
                success=False,
                sled_bytes=b"",
                nop_name=self.NAME,
                error=str(exc),
            )

        # Validate that the implementation honoured the badchars constraint.
        hit = next((b for b in sled if b in badchars), None)
        if hit is not None:
            return NopsResult(
                success=False,
                sled_bytes=b"",
                nop_name=self.NAME,
                error=(f"generate_sled returned a sled containing bad byte 0x{hit:02x}."),
            )

        return NopsResult(success=True, sled_bytes=sled, nop_name=self.NAME)

    def can_avoid(self, badchars: frozenset[int]) -> bool:
        """Return True when this module *might* be able to avoid *badchars*."""
        _badchars = badchars
        return True

    def generate_sled(self, size: int, badchars: frozenset[int]) -> bytes:
        """Generate and return a NOP sled of exactly *size* bytes."""
        raise NotImplementedError(f"{self.__class__.__name__} must implement generate_sled().")
