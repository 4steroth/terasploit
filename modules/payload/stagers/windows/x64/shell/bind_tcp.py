from collections.abc import Mapping, Sequence

from teralibs.tsf.base.payload import (
    ARCH_X64,
    PLATFORM_WINDOWS,
    STAGER,
    Payload,
    PayloadHandler,
)
from teralibs.tsf.core.payload.windows.x64.bind_tcp_x64 import BindTcpX64


class TerasploitModule(BindTcpX64, Payload):
    """Windows x64 bind-TCP stager."""

    NAME: str = "Windows x64 Bind TCP Stager"
    DESCRIPTION: str = "Listen for a connection from the attacker (Windows x64)"
    AUTHOR: Sequence = ["hdm", "skape", "sf", "4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.1"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/windows/x64/bind_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/x64/bind_tcp.rb",
    ]
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.BindTCP
    STAGE_PATH: str = "windows.x64.shell"
    CACHED_SIZE: int = 451
    MAX_SIZE: int | None = 512
    ARCH: Sequence = [ARCH_X64]
    PLATFORM: Sequence = [PLATFORM_WINDOWS]
    STAGER_CONF: Mapping = {"RequiresMidstager": False}
