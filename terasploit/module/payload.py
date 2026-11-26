from collections.abc import Mapping, Sequence

from extension.handler.constants import Handler
from extension.module.base import Base


# Payload type constants

#: Fully self-contained single-delivery payload.
SINGLE = "single"

#: First-stage stub; opens a channel and waits for the companion stage.
STAGER = "stager"

#: Second-stage payload delivered over the stager's channel.
STAGE = "stage"

#: Wraps a single payload to run it via a different transport.
ADAPTER = "adapter"

# Payload Handler
PayloadHandler = Handler


class Payload(Base):
    """Base class for Terasploit payload modules."""

    HANDLER: object = None
    PAYLOAD_TYPE: str = SINGLE
    STAGE_PATH: str = ""
    WRAPPED_PAYLOAD_PATH: str = ""
    ARCH: Sequence
    PLATFORM: Sequence
    MAX_SIZE: int | None = None
    CACHED_SIZE: int = -1
    BADCHARS: str = ""
    STAGE_ENCODING: bool = False
    STAGER_CONF: Mapping = {}
    SAVE_REGISTERS: str | None = None
    STAGE_PREFIX: str = ""

    def generate(self, ctx) -> bytes | str:
        """Return the payload bytes to be delivered by the exploit module."""
        return b""

    def generate_stage(self, ctx) -> bytes:
        """Return the stage bytes sent by the framework over the stager channel."""
        _ctx = ctx
        return b""

    def compatible(self, cached_size) -> bool:
        """Return whether this payload is compatible with the calling adapter."""
        _cached_size = cached_size
        return True
