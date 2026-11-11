import re
import struct

from teralibs.tsf.pex.architecture.aarch64 import AARCH64
from teralibs.tsf.pex.architecture.amd64 import AMD64
from teralibs.tsf.pex.architecture.arm import ARM
from teralibs.tsf.pex.architecture.loongarch64 import LOONGARCH64
from teralibs.tsf.pex.architecture.mips32 import MIPS32
from teralibs.tsf.pex.architecture.mips64 import MIPS64
from teralibs.tsf.pex.architecture.ppc32 import PPC32
from teralibs.tsf.pex.architecture.ppc64 import PPC64
from teralibs.tsf.pex.architecture.riscv32 import RISCV32
from teralibs.tsf.pex.architecture.riscv64 import RISCV64
from teralibs.tsf.pex.architecture.sparc import SPARC
from teralibs.tsf.pex.architecture.x86 import ARCHX86
from teralibs.tsf.pex.architecture.zarch import ZARCH


__all__ = [
    "AARCH64",
    "AMD64",
    "ARCHX86",
    "ARCH_AARCH64",
    "ARCH_ALL",
    "ARCH_ARMBE",
    "ARCH_ARMLE",
    "ARCH_BASH",
    "ARCH_CBEA",
    "ARCH_CBEA64",
    "ARCH_CMD",
    "ARCH_DALVIK",
    "ARCH_FIREFOX",
    "ARCH_JAVA",
    "ARCH_LOONGARCH64",
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
    "ARCH_R",
    "ARCH_RISCV32BE",
    "ARCH_RISCV32LE",
    "ARCH_RISCV64BE",
    "ARCH_RISCV64LE",
    "ARCH_RUBY",
    "ARCH_SPARC",
    "ARCH_SPARC64",
    "ARCH_TTY",
    "ARCH_X64",
    "ARCH_X86",
    "ARCH_X86_64",
    "ARCH_ZARCH",
    "ARM",
    "ENDIAN_BIG",
    "ENDIAN_LITTLE",
    "IS_ENDIAN_BIG",
    "IS_ENDIAN_LITTLE",
    "LOONGARCH64",
    "MIPS32",
    "MIPS64",
    "PPC32",
    "PPC64",
    "RISCV32",
    "RISCV64",
    "SPARC",
    "ZARCH",
    "Arch",
]

ENDIAN_LITTLE = 0
ENDIAN_BIG = 1

IS_ENDIAN_LITTLE = struct.pack("@h", 1) == b"\x01\x00"
IS_ENDIAN_BIG = not IS_ENDIAN_LITTLE


# CORE ARCHITECTURE CONSTANTS & CONFIGURATIONS

ARCH_X86 = "x86"
ARCH_X86_64 = "x86_64"
ARCH_X64 = "x64"  # To be used for compatability with ARCH_X86_64
ARCH_MIPS = "mips"
ARCH_MIPSLE = "mipsle"
ARCH_MIPSBE = "mipsbe"
ARCH_MIPS64 = "mips64"
ARCH_MIPS64LE = "mips64le"
ARCH_PPC = "ppc"
ARCH_PPCE500V2 = "ppce500v2"
ARCH_PPC64 = "ppc64"
ARCH_PPC64LE = "ppc64le"
ARCH_CBEA = "cbea"
ARCH_CBEA64 = "cbea64"
ARCH_SPARC = "sparc"
ARCH_SPARC64 = "sparc64"
ARCH_ARMLE = "armle"
ARCH_ARMBE = "armbe"
ARCH_AARCH64 = "aarch64"
ARCH_BASH = "bash"
ARCH_CMD = "cmd"
ARCH_PHP = "php"
ARCH_TTY = "tty"
ARCH_JAVA = "java"
ARCH_LUA = "lua"
ARCH_RUBY = "ruby"
ARCH_DALVIK = "dalvik"
ARCH_PERL = "perl"
ARCH_PYTHON = "python"
ARCH_NODEJS = "nodejs"
ARCH_FIREFOX = "firefox"
ARCH_ZARCH = "zarch"
ARCH_R = "r"
ARCH_RISCV32BE = "riscv32be"
ARCH_RISCV32LE = "riscv32le"
ARCH_RISCV64BE = "riscv64be"
ARCH_RISCV64LE = "riscv64le"
ARCH_LOONGARCH64 = "loongarch64"

# High-level architecture catalog matching framework scopes
ARCH_ALL = "all"


class Arch:
    """Architecture class."""

    @staticmethod
    def pack_addr(arch, addr):
        """Return the correct struct format according to architecture."""
        if isinstance(arch, (list, tuple)):
            arch = arch[0]

        # Map each architecture to its corresponding struct format string
        formats = {
            # 32-bit Little Endian ('V' -> '<I')
            ARCH_X86: "<I",
            ARCH_MIPSLE: "<I",
            ARCH_ARMLE: "<I",
            ARCH_RISCV32LE: "<I",
            # 32-bit Big Endian ('N' -> '>I')
            ARCH_MIPS: ">I",  # ambiguous
            ARCH_MIPSBE: ">I",
            ARCH_PPC: ">I",  # ambiguous
            ARCH_PPCE500V2: ">I",
            ARCH_SPARC: ">I",
            ARCH_ARMBE: ">I",
            ARCH_RISCV32BE: ">I",
            # 64-bit Little Endian ('Q<' -> '<Q')
            ARCH_X86_64: "<Q",
            ARCH_X64: "<Q",
            ARCH_MIPS64LE: "<Q",
            ARCH_PPC64LE: "<Q",
            ARCH_AARCH64: "<Q",
            ARCH_RISCV64LE: "<Q",
            ARCH_LOONGARCH64: "<Q",
            # 64-bit Big Endian ('Q>' -> '>Q')
            ARCH_MIPS64: ">Q",
            ARCH_SPARC64: ">Q",
            ARCH_ZARCH: ">Q",
            ARCH_RISCV64BE: ">Q",
        }

        fmt = formats.get(arch)
        if fmt:
            return struct.pack(fmt, addr)
        return None

    @staticmethod
    def endian(arch):
        """Return the endianness constant for the given target architecture."""
        if isinstance(arch, (list, tuple)):
            arch = arch[0]

        big_endian_archs = {
            ARCH_MIPS,  # ambiguous
            ARCH_MIPSBE,
            ARCH_MIPS64,
            ARCH_PPC,  # ambiguous
            ARCH_PPCE500V2,
            ARCH_SPARC,
            ARCH_SPARC64,
            ARCH_ARMBE,
            ARCH_ZARCH,
            ARCH_RISCV32BE,
            ARCH_RISCV64BE,
        }

        if arch in big_endian_archs:
            return ENDIAN_BIG

        return ENDIAN_LITTLE

    @staticmethod
    def from_uname(uname_arch):
        """Map a uname architecture string to its corresponding architecture constant."""
        if uname_arch is None:
            return None

        normalized = str(uname_arch).lower().strip()

        exact_matches = {
            "x86_64": ARCH_X64,
            "x64": ARCH_X64,
            "amd64": ARCH_X64,
            "i686": ARCH_X86,
            "i386": ARCH_X86,
            "i486": ARCH_X86,
            "i586": ARCH_X86,
            "aarch64": ARCH_AARCH64,
            "arm64": ARCH_AARCH64,
            "mips": ARCH_MIPSBE,
            "mipsel": ARCH_MIPSLE,
            "mips64": ARCH_MIPS64,
            "mips64el": ARCH_MIPS64LE,
            "ppc": ARCH_PPC,
            "ppc64": ARCH_PPC64,
            "ppc64le": ARCH_PPC64LE,
            "s390x": ARCH_ZARCH,
            "sparc": ARCH_SPARC,
            "sparc64": ARCH_SPARC64,
            "riscv32": ARCH_RISCV32LE,
            "riscv64": ARCH_RISCV64LE,
            "loongarch64": ARCH_LOONGARCH64,
        }

        if normalized in exact_matches:
            return exact_matches[normalized]

        if re.fullmatch(r"armv[0-9].*l", normalized):
            return ARCH_ARMLE

        if re.fullmatch(r"armv[0-9].*b", normalized):
            return ARCH_ARMBE

        return None
