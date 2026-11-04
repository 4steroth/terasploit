# cpu.py - CPU architecture descriptors for terasm.
#
# Inspired by metasm's CPU class hierarchy. Each CPU object bundles
# the arch constant, mode flags, and default syntax into one value.
#
# Usage:
#   cpu = CPU.x86(32)                  # x86 32-bit, Intel syntax (default)
#   cpu = CPU.x86(64, syntax="att")    # x86 64-bit, AT&T syntax
#   cpu = CPU.arm()                    # ARM little-endian
#   cpu = CPU.arm(thumb=True)          # ARM Thumb mode
#   cpu = CPU.mips(64, big_endian=True)
#
# CPU instances are named tuples - immutable, hashable, safe to pass around.

from collections import namedtuple

from teralibs.tsf.pex.terasm.terasm_const import (
    TA_ARCH_ARM,
    TA_ARCH_ARM64,
    TA_ARCH_EVM,
    TA_ARCH_HEXAGON,
    TA_ARCH_MIPS,
    TA_ARCH_PPC,
    TA_ARCH_SPARC,
    TA_ARCH_SYSTEMZ,
    TA_ARCH_X86,
    TA_MODE_16,
    TA_MODE_32,
    TA_MODE_64,
    TA_MODE_ARM,
    TA_MODE_BIG_ENDIAN,
    TA_MODE_LITTLE_ENDIAN,
    TA_MODE_MICRO,
    TA_MODE_MIPS3,
    TA_MODE_MIPS32,
    TA_MODE_MIPS32R6,
    TA_MODE_MIPS64,
    TA_MODE_PPC32,
    TA_MODE_PPC64,
    TA_MODE_SPARC32,
    TA_MODE_SPARC64,
    TA_MODE_THUMB,
    TA_MODE_V8,
    TA_MODE_V9,
    TA_OPT_SYNTAX_ATT,
    TA_OPT_SYNTAX_GAS,
    TA_OPT_SYNTAX_INTEL,
    TA_OPT_SYNTAX_NASM,
)


# Internal: immutable architecture descriptor
_CPUBase = namedtuple("CPU", ["arch", "mode", "syntax", "name"])


# Syntax name → constant
_SYNTAX_MAP = {
    "intel": TA_OPT_SYNTAX_INTEL,
    "att": TA_OPT_SYNTAX_ATT,
    "nasm": TA_OPT_SYNTAX_NASM,
    "gas": TA_OPT_SYNTAX_GAS,
}


def _syntax_const(name: str | None) -> int | None:
    if name is None:
        return None
    key = name.lower()
    if key not in _SYNTAX_MAP:
        raise ValueError(f"Unknown syntax {name!r}. Valid options: {list(_SYNTAX_MAP)}")
    return _SYNTAX_MAP[key]


class CPU(_CPUBase):
    """
    Immutable descriptor for a target CPU architecture.

    Fields (namedtuple):
        arch    - TA_ARCH_* constant
        mode    - combined TA_MODE_* flags
        syntax  - TA_OPT_SYNTAX_* constant or None
        name    - human-readable label (e.g. "x86-64-intel")

    Do not construct directly - use the class-level factory methods.
    """

    # x86 / x86-64

    @classmethod
    def x86(cls, bits: int = 32, syntax: str = "intel") -> CPU:
        """
        x86 or x86-64 CPU.
        """
        _mode_map = {16: TA_MODE_16, 32: TA_MODE_32, 64: TA_MODE_64}
        if bits not in _mode_map:
            raise ValueError(f"x86 bits must be 16, 32, or 64 - got {bits}")
        return cls(
            arch=TA_ARCH_X86,
            mode=_mode_map[bits],
            syntax=_syntax_const(syntax),
            name=f"x86-{bits}-{syntax.lower()}",
        )

    # ARM

    @classmethod
    def arm(
        cls,
        thumb: bool = False,
        big_endian: bool = False,
        v8: bool = False,
    ) -> CPU:
        """
        ARM CPU (32-bit).
        """
        # TA_MODE_ARM and TA_MODE_THUMB are mutually exclusive in keystone.
        # Thumb mode uses TA_MODE_THUMB as the base; ARM mode uses TA_MODE_ARM.
        mode = TA_MODE_THUMB if thumb else TA_MODE_ARM
        if big_endian:
            mode |= TA_MODE_BIG_ENDIAN
        else:
            mode |= TA_MODE_LITTLE_ENDIAN
        if v8:
            mode |= TA_MODE_V8

        label = "arm-thumb" if thumb else "arm"
        if big_endian:
            label += "-be"
        return cls(arch=TA_ARCH_ARM, mode=mode, syntax=None, name=label)

    # ARM64 / AArch64

    @classmethod
    def arm64(cls) -> CPU:
        """ARM64 / AArch64 CPU."""
        return cls(
            arch=TA_ARCH_ARM64,
            mode=TA_MODE_LITTLE_ENDIAN,
            syntax=None,
            name="arm64",
        )

    # MIPS

    @classmethod
    def mips(
        cls,
        bits: int = 32,
        big_endian: bool = False,
        micro: bool = False,
        mips3: bool = False,
        mips32r6: bool = False,
    ) -> CPU:
        """
        MIPS CPU.
        """
        if bits not in (32, 64):
            raise ValueError(f"MIPS bits must be 32 or 64 - got {bits}")
        mode = TA_MODE_MIPS32 if bits == 32 else TA_MODE_MIPS64
        if big_endian:
            mode |= TA_MODE_BIG_ENDIAN
        else:
            mode |= TA_MODE_LITTLE_ENDIAN
        if micro:
            mode |= TA_MODE_MICRO
        if mips3:
            mode |= TA_MODE_MIPS3
        if mips32r6:
            mode |= TA_MODE_MIPS32R6

        label = f"mips{bits}"
        if big_endian:
            label += "-be"
        return cls(arch=TA_ARCH_MIPS, mode=mode, syntax=None, name=label)

    # PowerPC

    @classmethod
    def ppc(cls, bits: int = 32, big_endian: bool = True) -> CPU:
        """
        PowerPC CPU.

        Args:
            bits        - 32 or 64 (default 32)
            big_endian  - use big-endian byte order (default True - PPC convention)
        """
        if bits not in (32, 64):
            raise ValueError(f"PPC bits must be 32 or 64 - got {bits}")
        mode = TA_MODE_PPC32 if bits == 32 else TA_MODE_PPC64
        mode |= TA_MODE_BIG_ENDIAN if big_endian else TA_MODE_LITTLE_ENDIAN
        label = f"ppc{bits}"
        if not big_endian:
            label += "-le"
        return cls(arch=TA_ARCH_PPC, mode=mode, syntax=None, name=label)

    # SPARC

    @classmethod
    def sparc(cls, bits: int = 32, v9: bool = False) -> CPU:
        """
        SPARC CPU.

        Args:
            bits - 32 or 64 (default 32)
            v9   - enable SPARC V9 ISA (default False)
        """
        if bits not in (32, 64):
            raise ValueError(f"SPARC bits must be 32 or 64 - got {bits}")
        mode = TA_MODE_SPARC32 if bits == 32 else TA_MODE_SPARC64
        mode |= TA_MODE_BIG_ENDIAN
        if v9:
            mode |= TA_MODE_V9
        label = f"sparc{bits}" + ("-v9" if v9 else "")
        return cls(arch=TA_ARCH_SPARC, mode=mode, syntax=None, name=label)

    # SystemZ (IBM s390x)

    @classmethod
    def systemz(cls) -> CPU:
        """IBM SystemZ / s390x CPU."""
        return cls(
            arch=TA_ARCH_SYSTEMZ,
            mode=TA_MODE_BIG_ENDIAN,
            syntax=None,
            name="systemz",
        )

    # Qualcomm Hexagon

    @classmethod
    def hexagon(cls) -> CPU:
        """Qualcomm Hexagon DSP CPU."""
        return cls(
            arch=TA_ARCH_HEXAGON,
            mode=TA_MODE_LITTLE_ENDIAN,
            syntax=None,
            name="hexagon",
        )

    # EVM (Ethereum Virtual Machine)

    @classmethod
    def evm(cls) -> CPU:
        """Ethereum Virtual Machine (EVM) bytecode."""
        return cls(
            arch=TA_ARCH_EVM,
            mode=0,
            syntax=None,
            name="evm",
        )

    # Repr

    def __repr__(self):
        return f"<CPU {self.name}>"
