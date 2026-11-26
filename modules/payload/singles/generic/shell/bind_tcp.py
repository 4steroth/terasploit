from collections.abc import Sequence

from libs.arch import ARCH_ALL
from libs.platform import PLATFORM_ALL
from terasploit.module.payload import (
    SINGLE,
    Payload,
    PayloadHandler,
)


class TerasploitModule(Payload):
    """Generic payload for shell session via bind tcp connection."""

    NAME: str = "Generic Bind Shell (Single)"
    DESCRIPTION: str = "Listen for a connection on the target and spawn a command shell."
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = []
    PAYLOAD_TYPE: str = SINGLE
    HANDLER: object = PayloadHandler.BindTCP
    CACHED_SIZE: int = 0
    MAX_SIZE: int | None = 4096
    ARCH: Sequence = [ARCH_ALL]
    PLATFORM: Sequence = [PLATFORM_ALL]
    OPTIONS: Sequence = ["LPORT", "RHOST"]
