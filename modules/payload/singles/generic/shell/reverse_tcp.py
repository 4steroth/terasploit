from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_ALL, PLATFORM_ALL, SINGLE, Payload, PayloadHandler


class TerasploitModule(Payload):
    """Generic payload for shell session via reverse tcp connection."""

    NAME: str = "Generic Reverse Shell (Single)"
    DESCRIPTION: str = "Connect back to attacker and spawn a command shell."
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = []
    PAYLOAD_TYPE: str = SINGLE
    HANDLER: object = PayloadHandler.ReverseTCP
    CACHED_SIZE: int = 0
    MAX_SIZE: int | None = 4096
    ARCH: Sequence = [ARCH_ALL]
    PLATFORM: Sequence = [PLATFORM_ALL]
    OPTIONS: Sequence = ["LHOST", "LPORT"]
