class EncoderState:
    """Track the state of a single encoding operation."""

    def __init__(self, key=None):
        """Initialize the encoder state."""
        self.key = None
        self.orig_key = None
        self.encoded = b""
        self.context = None
        self.badchars = None

        self.context_encoding = False
        self.context_address = None

        self.decoder_key_offset = None
        self.decoder_key_size = None
        self.decoder_key_pack = None
        self.decoder_stub = None

        self._orig_buf = None
        self._buf = None

        self.reset(key)

    def reset(self, key=None):
        """Reset the encoder state."""
        self.init_key(key)
        self.encoded = b""

    def init_key(self, key):
        """Set the initial encoding key."""
        self.key = key
        self.orig_key = key

    @property
    def buf(self):
        """Return the current encoding buffer."""
        return self._buf

    @buf.setter
    def buf(self, buf):
        """Set the encoding buffer and preserve its original value."""
        if not isinstance(buf, bytes):
            raise TypeError("Encoder buffer must be bytes")

        if self._orig_buf is None or self._buf is None:
            self._orig_buf = buf

        self._buf = buf

    @property
    def orig_buf(self):
        """Return the original encoding buffer."""
        return self._orig_buf


class BadcharError(Exception):
    """Represent a forbidden byte discovered during encoding."""

    def __init__(self, index, stub_size, message=""):
        """Initialize the bad-character error."""
        super().__init__(message)
        self.index = index
        self.stub_size = stub_size
