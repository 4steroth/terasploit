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


class Evasion(Base):
    """
    Mixin that marks an :class:`Exploit` subclass as a standalone evasion module.

    Class attributes:

    EVASION_TECHNIQUE : str
        Short human-readable label for the primary evasion technique used
        (e.g. ``"process hollowing"``, ``"AMSI bypass"``).
        Shown in the module listing and ``info`` output.

    NEEDS_CLEANUP : bool
        Declare ``True`` when ``run()`` leaves artefacts on the target
        (dropped files, injected threads, registry keys) that ``cleanup()``
        should remove.  Defaults to ``False``.
    """

    #: Short description of the evasion technique (required by convention).
    EVASION_TECHNIQUE: str = ""

    #: True when the module leaves artefacts that cleanup() must remove.
    NEEDS_CLEANUP: bool = False

    def cleanup(self, ctx) -> None:
        """
        Remove any artefacts left on the target after ``run()`` completes.

        Override this method when :attr:`NEEDS_CLEANUP` is ``True``.
        Called by the framework after ``run()`` returns regardless of whether
        it succeeded or raised.  The default implementation is a no-op.
        """

    def needs_cleanup(self) -> bool:
        """
        Return ``True`` when this module requires a cleanup pass.

        Convenience wrapper around :attr:`NEEDS_CLEANUP` for code that
        prefers the method form (mirrors the MSF contract).
        """
        return bool(self.NEEDS_CLEANUP)
