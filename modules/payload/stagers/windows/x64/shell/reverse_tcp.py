from collections.abc import Mapping, Sequence

from teralibs.tsf.base.payload import (
    ARCH_X64,
    PLATFORM_WINDOWS,
    STAGER,
    Payload,
    PayloadHandler,
)
from teralibs.tsf.core.payload.windows.x64.reverse_tcp_x64 import ReverseTcpX64


class TerasploitModule(ReverseTcpX64, Payload):
    """Windows x64 reverse-TCP stager."""

    NAME: str = "Windows x64 Reverse TCP Stager"
    DESCRIPTION: str = "Connect back to the attacker (Windows x64)"
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.1"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/windows/x64/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/x64/reverse_tcp.rb",
    ]
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.ReverseTCP
    STAGE_PATH: str = "windows.x64.shell"
    CACHED_SIZE: int = 449
    MAX_SIZE: int | None = 512
    ARCH: Sequence = [ARCH_X64]
    PLATFORM: Sequence = [PLATFORM_WINDOWS]
    STAGER_CONF: Mapping = {"RequiresMidstager": False}
