import random
from collections.abc import Sequence, Set as AbstractSet

from teralibs.tsf.base.encoder import ARCH_X64, Encoder, EncoderRank, EncoderResult
from teralibs.tsf.core.encoder.xor_dynamic import XorDynamic


class TerasploitModule(XorDynamic, Encoder):
    """x86-64 single-byte XOR encoder."""

    NAME: str = "x64 XOR Dynamic"
    DESCRIPTION: str = (
        "x86-64 single-byte XOR encoder with a RIP-relative self-decoding "
        "stub (24 bytes).  Iterates key candidates 0x01-0xff, picks the "
        "first that produces a clean full output (stub + encoded payload).  "
        "Requires 0x00 to be clean (LEA displacement).  Ranked GREAT.  "
        "Bad characters are specified via 'set BADCHARS' on the payload, "
        "not on this encoder."
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: int = EncoderRank.GREAT
    REFERENCES: Sequence = []
    ARCH: Sequence = [ARCH_X64]
    MAX_ITERATIONS: int = 255

    def find_key(self, buf: bytes, badchars: bytes | AbstractSet[int], *args, **kwargs) -> bytes | None:
        """Find a rolling XOR key that avoids all bad characters."""
        key_chars = args[0] if args else kwargs.get("key_chars")
        if key_chars is None:
            raise ValueError("Key characters are required.")

        buf_len = len(buf)
        min_len, max_len, key_inc = self._resolve_key_config(
            buf_len,
            len(badchars),
        )

        key_len = min_len
        while key_len <= max_len:
            candidate = self._build_key(
                buf,
                badchars,
                key_chars,
                key_len,
            )

            if candidate is not None:
                return candidate

            key_len += key_inc

        return None

    def _resolve_key_config(self, buf_len: int, badchar_count: int) -> tuple[int, int, int]:
        """Resolve effective key search parameters."""
        min_len = self.min_key_len()

        if min_len < 1:
            min_len = int((buf_len // 100) * (0.2 + 0.05 * badchar_count))
            min_len = max(min_len, 1)

        max_len = self.max_key_len()
        if max_len < 1:
            max_len = buf_len

        if min_len > max_len or self.min_key_len() == -1:
            min_len = max_len

        key_inc = self.key_inc()
        if key_inc < 1:
            key_inc = int((buf_len // 100) * (0.01 + 0.001 * badchar_count))
            key_inc = max(key_inc, 1)

        return min_len, max_len, key_inc

    def _build_key(self, buf: bytes, badchars: bytes | AbstractSet[int], key_chars: bytes, key_len: int) -> bytes | None:
        """Attempt to construct a valid XOR key for the specified key length."""
        key = bytearray()

        for offset in range(key_len):
            key_byte = self._find_key_byte(
                buf,
                badchars,
                (key_chars, key_len),
                offset,
            )

            if key_byte is None:
                return None
            key.append(key_byte)

        return bytes(key)

    def _find_key_byte(self, buf: bytes, badchars: bytes | AbstractSet[int], key: tuple[bytes, int], offset: int) -> int | None:
        """Find a valid key byte for a specific rolling XOR position."""
        key_chars, key_len = key
        buf_len = len(buf)

        for candidate in key_chars:
            if self._is_valid_key_byte(
                buf,
                badchars,
                candidate,
                (key_len, buf_len),
                offset,
            ):
                return candidate

        return None

    @staticmethod
    def _is_valid_key_byte(buf: bytes, badchars: bytes | AbstractSet[int], candidate: int, length: tuple[int, int], offset: int) -> bool:
        """Validate whether a candidate XOR byte avoids all bad characters."""
        key_len, buf_len = length
        index = offset

        while index < buf_len:
            if buf[index] ^ candidate in badchars:
                return False
            index += key_len

        return True

    def encode(self, raw_bytes: bytes, bad_bytes: frozenset[int], ctx: object | None = None):
        """Encode the raw payload using a variable-length rolling XOR key."""
        bad_bytes = bad_bytes or frozenset()
        try:
            self._validate_stub(bad_bytes)

            key_chars = bytes(value for value in range(1, 256) if value not in bad_bytes)
            key = self.find_key(
                raw_bytes,
                bytes(bad_bytes),
                key_chars,
                self.DATASTORE,
            )

            if key is None:
                raise ValueError("Could not generate a valid XOR key.")

            key_term = self._find_key_terminator(
                key,
                key_chars,
            )

            encoded = self._xor_encode(
                raw_bytes,
                key,
            )

            payload_term = self._find_payload_terminator(
                encoded,
                key_chars,
            )

            full_output = self._build_output(
                key,
                key_term,
                encoded,
                payload_term,
            )

            self._validate_output(
                full_output,
                bad_bytes,
            )

        except ValueError as exc:
            return EncoderResult(
                success=False,
                encoded_bytes=b"",
                encoder_name=self.NAME,
                error=f"[{self.NAME}] {exc}",
            )

        return EncoderResult(
            success=True,
            encoded_bytes=full_output,
            encoder_name=self.NAME,
            key_used=int.from_bytes(key, byteorder="big"),
            iterations=1,
        )

    def _validate_stub(self, bad_bytes: frozenset[int]) -> None:
        """Ensure the static stub does not already contain restricted bytes."""
        cleaned_stub = self.stub().replace(self.stub_key_term(), b"").replace(self.stub_payload_term(), b"")

        violations = {byte for byte in cleaned_stub if byte in bad_bytes}

        if violations:
            formatted = " ".join(f"0x{byte:02x}" for byte in sorted(violations))
            raise ValueError(f"Stub contains bad bytes: {formatted}")

    def _find_key_terminator(self, key: bytes, key_chars: bytes) -> bytes:
        """Find a single-byte terminator that does not appear inside the XOR key."""
        candidates = list(key_chars)
        random.shuffle(candidates)

        for value in candidates:
            if value not in key:
                return bytes([value])

        raise ValueError("Failed to locate a valid key terminator.")

    def _xor_encode(self, raw_bytes: bytes, key: bytes) -> bytes:
        """Apply rolling XOR encoding."""
        key_len = len(key)

        return bytes(raw_byte ^ key[index % key_len] for index, raw_byte in enumerate(raw_bytes))

    def _find_payload_terminator(self, encoded: bytes, key_chars: bytes) -> bytes:
        """Find a unique 2-byte payload terminator that does not exist in the encoded payload."""
        outer = list(key_chars)
        inner = list(key_chars)

        random.shuffle(outer)

        for first in outer:
            random.shuffle(inner)

            for second in inner:
                candidate = bytes([first, second])

                if candidate not in encoded:
                    return candidate

        raise ValueError("Failed to locate a valid payload terminator.")

    def _build_output(self, key: bytes, key_term: bytes, encoded: bytes, payload_term: bytes) -> bytes:
        """Patch the decoder stub and assemble the final payload."""
        stub = self.stub().replace(self.stub_key_term(), key_term).replace(self.stub_payload_term(), payload_term)

        return stub + key + key_term + encoded + payload_term

    def _validate_output(self, output: bytes, bad_bytes: frozenset[int]) -> None:
        """Ensure the final payload does not contain restricted bytes."""
        violations = {byte for byte in output if byte in bad_bytes}

        if violations:
            formatted = " ".join(f"0x{byte:02x}" for byte in sorted(violations))

            raise ValueError(f"Final payload contains bad bytes: {formatted}")

    def can_avoid(self, bad_bytes: frozenset[int]) -> bool:
        """Pre-screen method to quickly determine if encoding is inherently impossible."""
        if not bad_bytes:
            return True

        # Strip out the placeholders inside the stub to evaluate static bytes
        cleaned_stub = self.stub().replace(self.stub_key_term(), b"").replace(self.stub_payload_term(), b"")

        # If any constant, unalterable assembly byte in the stub is blocked, reject immediately.
        return all(b not in bad_bytes for b in cleaned_stub)
