import struct

from teralibs.tsf.base.encoder import Encoder, EncoderError, EncoderState
from teralibs.tsf.core.encoder.state import BadcharError


class XorAdditiveFeedback(Encoder):
    """Encodes a block using the XOR additive feedback algorithm."""

    def encode_block(self, state, block):
        """Encodes a block using the XOR additive feedback algorithm."""
        orig = struct.unpack(self.decoder_key_pack(), block)[0]
        oblock = orig ^ state.key
        state.key = (state.key + orig) % (1 << (self.decoder_key_size() * 8))
        return struct.pack(self.decoder_key_pack(), oblock)

    def find_key(self, buf, badchars, *args, **kwargs):
        """Finds a key that is compatible with the badchars list."""
        state = args[0] if args else kwargs.get("state")

        if state is None:
            state = EncoderState()

        base_key = super().find_key(buf, badchars, None)
        if base_key is None:
            return None

        key_bytes = self.integer_to_key_bytes(base_key)
        valid = False
        orig_key_bytes = key_bytes.copy()

        while not valid:
            self.init_state(state)
            try:
                state.reset(self.key_bytes_to_integer(key_bytes))
                if state.key is None:
                    raise EncoderError("Failed to initialize encoder key.")

                key_buffer = struct.pack(self.decoder_key_pack(), state.key)
                idx = self.has_badchars(key_buffer, badchars)
                if idx is not None:
                    raise BadcharError(
                        index=idx,
                        stub_size=0,
                        message="Key contains a bad character.",
                    )

                valid = self.do_encode(state)

            except BadcharError as info:
                if info.index < info.stub_size:
                    raise BadcharError(
                        index=info.index,
                        stub_size=info.stub_size,
                        message=f"The {self.NAME} decoder stub contains a bad character.",
                    ) from info

                idx = (info.index - info.stub_size) % self.decoder_key_size()

                key_bytes[idx] = (key_bytes[idx] + 1) % 255
                if key_bytes[idx] == orig_key_bytes[idx]:
                    raise BadcharError(
                        index=info.index,
                        stub_size=info.stub_size,
                        message=f"The {self.NAME} encoder failed to encode without bad characters.",
                    ) from info

        return state.orig_key
