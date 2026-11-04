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
from teralibs.tsf.pex.platform import (
    PLATFORM_AIX,
    PLATFORM_ALL,
    PLATFORM_ANDROID,
    PLATFORM_APPLE_IOS,
    PLATFORM_BSD,
    PLATFORM_CHROME,
    PLATFORM_CISCO,
    PLATFORM_FIREFOX,
    PLATFORM_FREEBSD,
    PLATFORM_HARDWARE,
    PLATFORM_HPUX,
    PLATFORM_IRIX,
    PLATFORM_JAVA,
    PLATFORM_JUNIPER,
    PLATFORM_LINUX,
    PLATFORM_MAINFRAME,
    PLATFORM_NETBSD,
    PLATFORM_NETWARE,
    PLATFORM_NODEJS,
    PLATFORM_OPENBSD,
    PLATFORM_OSX,
    PLATFORM_PERL,
    PLATFORM_PHP,
    PLATFORM_PYTHON,
    PLATFORM_RUBY,
    PLATFORM_SOLARIS,
    PLATFORM_UNIX,
    PLATFORM_WINDOWS,
)


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
    # Platforms
    "PLATFORM_AIX",
    "PLATFORM_ALL",
    "PLATFORM_ANDROID",
    "PLATFORM_APPLE_IOS",
    "PLATFORM_BSD",
    "PLATFORM_CHROME",
    "PLATFORM_CISCO",
    "PLATFORM_FIREFOX",
    "PLATFORM_FREEBSD",
    "PLATFORM_HARDWARE",
    "PLATFORM_HPUX",
    "PLATFORM_IRIX",
    "PLATFORM_JAVA",
    "PLATFORM_JUNIPER",
    "PLATFORM_LINUX",
    "PLATFORM_MAINFRAME",
    "PLATFORM_NETBSD",
    "PLATFORM_NETWARE",
    "PLATFORM_NODEJS",
    "PLATFORM_OPENBSD",
    "PLATFORM_OSX",
    "PLATFORM_PERL",
    "PLATFORM_PHP",
    "PLATFORM_PYTHON",
    "PLATFORM_RUBY",
    "PLATFORM_SOLARIS",
    "PLATFORM_UNIX",
    "PLATFORM_WINDOWS",
]


class Auxiliary(Base):
    """Base class for Terasploit auxiliary modules."""

    #: Human-readable module name shown in the console.
    NAME: str

    #: One-paragraph description of the exploit.
    DESCRIPTION: str

    #: Author handle or contact information.
    AUTHOR: str

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

    #: Target platforms. Use the PLATFORM_* constants from
    #: core.payload.base. Use ["all"] to accept any platform.
    PLATFORM: Sequence

    #: Supported auxiliary mode.
    AUXILIARY_MODE: Sequence

    # Primary execution API

    def run(self, ctx):
        """Execute the auxiliary module."""

    def check(self, ctx):
        """Execute the check method of the auxiliary module."""

    def stop(self):
        """Optional teardown hook called when the module is unloaded."""
