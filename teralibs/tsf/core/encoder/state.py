import dataclasses
from collections.abc import Set
from dataclasses import field


@dataclasses.dataclass
class EncoderState:
    """
    Maintains the structural environment parameters, tracking buffers,
    and constraint criteria throughout a payload encoding lifecycle.
    """

    buf: bytes = b""
    badchars: bytes | Set[int] = b""
    context_encoding: bool = False
    key: int | None = None
    orig_key: int | None = None  # Original seed key used for encoding

    # Tracked internally, excluded from the generated __init__
    orig_buf: bytes = field(init=False)

    def __post_init__(self):
        # Keep an immutable reference to the original source structure
        self.orig_buf = self.buf

        # Convert input to a built-in set of integers for optimized lookups.
        # Python's set() constructor natively handles both bytes and Sets.
        self.badchars = set(self.badchars)

    def reset(self, new_buf: bytes):
        """Resets the state tracking data to handle a fresh encoding pass."""
        self.buf = new_buf
        self.orig_buf = new_buf


class BadcharError(Exception):
    """Raised when a forbidden byte is discovered during the encoding sequence."""

    def __init__(self, index: int, stub_size: int, message: str = ""):
        super().__init__(message)
        self.index = index  # Byte index where the bad character was found
        self.stub_size = stub_size  # Size of the decoder stub preceding the payload
