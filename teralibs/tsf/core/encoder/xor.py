import struct
from itertools import cycle

from teralibs.tsf.base.encoder import Encoder


class Xor(Encoder):
    """Encodes payload using XOR."""

    def encode_block(self, state, block):
        """Encodes a block of data using repeating-key XOR based on decoder key size."""
        # Match decoder_key_size directly like Ruby's case statement
        match state.decoder_key_size:
            case 8:  # Rex::Encoding::Xor::Qword.keysize
                pack_format = "Q"
            case 4:  # Rex::Encoding::Xor::Dword.keysize
                pack_format = "I"
            case 2:  # Rex::Encoding::Xor::Word.keysize
                pack_format = "H"
            case 1:  # Rex::Encoding::Xor::Byte.keysize
                pack_format = "B"
            case _:  # Default to Dword
                pack_format = "I"

        # Pack state.key using state.decoder_key_pack or the matched fallback format
        key_bytes = struct.pack(state.decoder_key_pack or pack_format, state.key)

        # Convert block to bytes if it's a string and apply repeating XOR
        block_bytes = block.encode("latin1") if isinstance(block, str) else bytes(block)
        return bytes(a ^ b for a, b in zip(block_bytes, cycle(key_bytes)))

    def find_bad_keys(self, buf, badchars):
        """Finds keys that are incompatible with the supplied bad character list."""
        # Short circuit if there are no badchars
        if len(badchars) == 0:
            return super().find_bad_keys(buf, badchars)

        bad_keys = [{} for _ in range(self.decoder_key_size())]

        # Scan through all the badchars and build out the bad_keys array
        # based on the XOR'd combinations that can occur at certain bytes
        # to produce bad characters
        for byte_idx, byte in enumerate(buf):
            for badchar in badchars:
                bad_keys[byte_idx % self.decoder_key_size()][byte ^ badchar] = True

        for badchar in badchars:
            for i in range(self.decoder_key_size()):
                bad_keys[i][badchar] = True

        return bad_keys
