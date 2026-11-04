import struct
from collections.abc import Set as AbstractSet

from teralibs.tsf.base.encoder import Encoder
from teralibs.tsf.core.encoder.state import BadcharError
from teralibs.tsf.core.module.base import Base


class XorAdditiveFeedback(Encoder, Base):
    """Encodes a block using the XOR additive feedback algorithm."""

    def encode_block(self, state, block: bytes) -> bytes:
        """
        XORs the current data block with the rolling cipher key,
        and adds the original data chunk back into the key state to
        provide the additive feedback mechanism.
        """
        key_pack_fmt = self.decoder_key_pack()
        key_size = self.decoder_key_size()

        # 1. Unpack the raw input block into an integer using the architecture's endianness
        # (e.g., unpacks a 4-byte DWORD from little-endian bytes)
        orig = struct.unpack(key_pack_fmt, block)[0]

        # 2. XOR the key with the current block integer
        oblock = orig ^ state.key

        # 3. Add the original unencoded block contents to the key state.
        # We apply a bitwise mask to perfectly simulate the x86 register overflow wrap-around
        # (e.g., 1 << 32 creates the boundary mask for a 32-bit EAX/EBX register)
        overflow_mask = (1 << (key_size * 8)) - 1
        state.key = (state.key + orig) & overflow_mask

        # 4. Pack the XOR'd block integer back into its original raw bytes layout
        return struct.pack(key_pack_fmt, oblock)

    def find_key(self, buf: bytes, badchars: bytes | AbstractSet[int], *args, **kwargs) -> int:
        """Finds a valid encryption key that evades bad characters."""
        state = args[0] if args else kwargs.get("state")
        if state is None:
            raise ValueError("Encoder state is required.")

        # --- 1. Initialization ---
        initial_seed_key = getattr(self, "get_initial_key", lambda b, bc: 0)(buf, badchars)
        key_size, key_pack_fmt = self._get_key_format_specs()

        key_bytes = bytearray(struct.pack(key_pack_fmt, initial_seed_key)[:key_size])
        orig_key_bytes = bytearray(key_bytes)

        # --- 2. Main Encoding Loop ---
        while True:
            self._reset_encoder_state(state, buf)
            try:
                self._apply_key_to_state(state, key_bytes, key_pack_fmt)
                self._validate_key_bytes(state, key_size, key_pack_fmt)

                if self.do_encode(state):
                    break
            except BadcharError as info:
                key_bytes = self._handle_badchar_error(info, key_bytes, orig_key_bytes, key_size)

        # --- 3. Return Verification ---
        if state.key is None:
            raise RuntimeError("State key was not set during encoding process.")
        return getattr(state, "orig_key", state.key)

    # Helper Methods (Internal API)

    def _get_key_format_specs(self) -> tuple[int, str]:
        """Retrieves the decoder key size and pack format structure safely."""
        key_size = self.decoder_key_size() if callable(getattr(self, "decoder_key_size", None)) else getattr(self, "decoder_key_size", 4)
        key_pack_fmt = self.decoder_key_pack() if callable(getattr(self, "decoder_key_pack", None)) else getattr(self, "decoder_key_pack", "<I")
        return key_size, key_pack_fmt

    def _reset_encoder_state(self, state, buf: bytes) -> None:
        """Resets the state object parameters for the current iteration try."""
        if hasattr(self, "init_state"):
            self.init_state(state)
        else:
            state.reset(buf)

    def _apply_key_to_state(self, state, key_bytes: bytearray, key_pack_fmt: str) -> None:
        """Syncs and unpacks working key bytes into state object integers."""
        current_key_int = struct.unpack(key_pack_fmt, key_bytes.ljust(4, b"\x00"))[0]
        state.key = current_key_int
        state.orig_key = current_key_int

    def _validate_key_bytes(self, state, key_size: int, key_pack_fmt: str) -> None:
        """Ensures the generated key integer contains no bad characters."""
        packed_key = struct.pack(key_pack_fmt, state.key)[:key_size]
        for idx, key_byte in enumerate(packed_key):
            if key_byte in state.badchars:
                raise BadcharError(index=idx, stub_size=0)

    def _handle_badchar_error(
        self,
        info: BadcharError,
        key_bytes: bytearray,
        orig_key_bytes: bytearray,
        key_size: int,
    ) -> bytearray:
        """Mutates key bytes or raises errors if complete wrap-around occurs."""
        encoder_name = getattr(self, "name", "Shikata")

        if info.index < info.stub_size:
            raise RuntimeError(f"The {encoder_name} decoder stub contains a bad character.") from info

        payload_bad_idx = info.index - info.stub_size
        key_mut_idx = payload_bad_idx % key_size

        key_bytes[key_mut_idx] = (key_bytes[key_mut_idx] + 1) % 256

        if key_bytes[key_mut_idx] == orig_key_bytes[key_mut_idx]:
            raise RuntimeError(f"The {encoder_name} encoder failed to encode without bad characters.") from info

        return key_bytes
