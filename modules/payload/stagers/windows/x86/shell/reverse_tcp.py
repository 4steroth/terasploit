from collections.abc import Mapping, Sequence

from teralibs.tsf.base.payload import (
    ARCH_X86,
    PLATFORM_WINDOWS,
    STAGER,
    Payload,
    PayloadHandler,
)
from teralibs.tsf.core.payload.windows.x86.reverse_tcp_x86 import ReverseTcpX86


class TerasploitModule(ReverseTcpX86, Payload):
    """Windows x86 reverse-TCP stager."""

    NAME: str = "Windows x86 Reverse TCP Stager"
    DESCRIPTION: str = "Connect back to the attacker (Windows x86)"
    AUTHOR: Sequence = ["hdm", "skape", "sf", "4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.1"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/windows/x86/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/x86/reverse_tcp.rb",
    ]
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.ReverseTCP
    STAGE_PATH: str = "windows.x86.shell"
    CACHED_SIZE: int = 297
    MAX_SIZE: int | None = 512
    ARCH: Sequence = [ARCH_X86]
    PLATFORM: Sequence = [PLATFORM_WINDOWS]
    STAGER_CONF: Mapping = {"RequiresMidstager": False}
