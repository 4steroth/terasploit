from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_CMD, PLATFORM_UNIX, SINGLE, Payload, PayloadHandler


class TerasploitModule(Payload):
    """Interact with Established Connection."""

    NAME: str = "Unix Command, Interact with Established Connection"
    DESCRIPTION: str = "Interacts with a shell on an established socket connection"
    AUTHOR: Sequence = ["hdm", "4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    RANK: str = "normal"
    REFERENCES: Sequence = ["MSF - cmd/unix/interact.rb"]
    PAYLOAD_TYPE: str = SINGLE
    HANDLER: object = PayloadHandler.FindShell
    CACHED_SIZE: int = 0
    ARCH: Sequence = [ARCH_CMD]
    PLATFORM: Sequence = [PLATFORM_UNIX]
