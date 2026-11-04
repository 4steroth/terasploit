import dataclasses
import os
import random
import struct
from collections.abc import Callable, Mapping, Sequence, Set as AbstractSet
from enum import IntEnum

from teralibs.tsf.core.encoder.state import BadcharError, EncoderState
from teralibs.tsf.core.module.base import Base
from teralibs.tsf.pex.arch import (
    ARCH_AARCH64,
    ARCH_ALL,
    ARCH_ARMBE,
    ARCH_ARMLE,
    ARCH_BASH,
    ARCH_CBEA,
    ARCH_CBEA64,
    ARCH_CMD,
    ARCH_JAVA,
    ARCH_LUA,
    ARCH_MIPS,
    ARCH_MIPS64,
    ARCH_MIPS64LE,
    ARCH_MIPSBE,
    ARCH_MIPSLE,
    ARCH_NODEJS,
    ARCH_PERL,
    ARCH_PHP,
    ARCH_PPC,
    ARCH_PPC64,
    ARCH_PPC64LE,
    ARCH_PPCE500V2,
    ARCH_PYTHON,
    ARCH_RUBY,
    ARCH_SPARC,
    ARCH_SPARC64,
    ARCH_TTY,
    ARCH_X64,
    ARCH_X86,
    ARCH_X86_64,
    ARCH_ZARCH,
)
from teralibs.tsf.utils.exception import EncoderError


# Everything in the module
__all__ = [
    # Architectures
    "ARCH_AARCH64",
    "ARCH_ALL",
    "ARCH_ARMBE",
    "ARCH_ARMLE",
    "ARCH_BASH",
    "ARCH_CBEA",
    "ARCH_CBEA64",
    "ARCH_CMD",
    "ARCH_JAVA",
    "ARCH_LUA",
    "ARCH_MIPS",
    "ARCH_MIPS64",
    "ARCH_MIPS64LE",
    "ARCH_MIPSBE",
    "ARCH_MIPSLE",
    "ARCH_NODEJS",
    "ARCH_PERL",
    "ARCH_PHP",
    "ARCH_PPC",
    "ARCH_PPC64",
    "ARCH_PPC64LE",
    "ARCH_PPCE500V2",
    "ARCH_PYTHON",
    "ARCH_RUBY",
    "ARCH_SPARC",
    "ARCH_SPARC64",
    "ARCH_TTY",
    "ARCH_X64",
    "ARCH_X86",
    "ARCH_X86_64",
    "ARCH_ZARCH",
]


class EncoderRank(IntEnum):
    """
    Numeric rank for encoder quality, used to sort the selection pipeline.

    Higher values mean the encoder is preferred over lower-ranked ones
    during automatic encoder selection.
    """

    MANUAL = 0
    LOW = 100
    NORMAL = 200
    GOOD = 300
    GREAT = 400
    EXCELLENT = 500

    def label(self) -> str:
        """Return the capitalised rank name (e.g. "Excellent")."""
        return self.name.capitalize()


@dataclasses.dataclass(slots=True)
class EncoderResult:
    """Outcome of a single :method:Encoder.encode call."""

    success: bool
    encoded_bytes: bytes
    encoder_name: str
    key_used: int | None = None
    iterations: int = 0
    error: str = ""

    #: Standalone decoder stub bytes.
    #: Empty when the stub is already prepended in encoded_bytes.
    #: When non-empty the assembler may use this to position the stub
    #: separately (e.g. in a different memory region).
    decoder_stub: bytes = b""

    def __repr__(self) -> str:
        return f"EncoderResult(success={self.success!r}, encoder={self.encoder_name!r}, key={self.key_used!r}, iters={self.iterations})"


class Utilities:
    """Utility methods for encoder implementations."""

    def encode_begin(self, state):
        """
        Called when encoding is about to start immediately after the encoding
        state has been initialized.
        """
        _state = state

    def encode_finalize_stub(self, state, stub):
        """
        This callback allows a derived class to finalize a stub after a key have
        been selected.  The finalized stub should be returned.
        """
        _state = state
        return stub

    def encode_end(self, state):
        """
        Called after encoding has completed.
        """
        _state = state

    def can_avoid(self, bad_bytes: frozenset[int]) -> bool:
        """Return True when this encoder *might* be able to avoid *bad_bytes*."""
        _bad_bytes = bad_bytes
        return True

    def decoder_stub(self, state) -> bytes:
        """Return the decoder stub bytes for this encoder, given the current state."""
        _state = state
        return b""

    def encode_block(self, state, block: bytes) -> bytes:
        """Encode a single block of bytes according to the encoder's algorithm."""
        # This method should be overridden by each specific encoder implementation
        # to perform the actual encoding transformation on the input block.
        _state = state
        return block

    def has_badchars(self, buf, badchars):
        """Check if any bad characters are present in the buffer."""
        for badchar in badchars:
            idx = buf.find(bytes([badchar]))
            if idx != -1:
                return idx
        return None

    def find_key_verify(self, buf, key_bytes, badchars):
        """
        Verify that the provided key bytes do not produce
        bad characters when applied to the buffer.
        """
        _buf, _key_bytes, _badchars = buf, key_bytes, badchars
        return True


class Encoder(Utilities, Base):
    """Base class for all Terasploit payload encoders."""

    #: Human-readable module name shown in the console.
    NAME: str

    #: One-paragraph description of the exploit.
    DESCRIPTION: str

    #: Author handle or contact information.
    AUTHOR: str | Sequence

    #: SPDX license identifier, e.g. "BSD-3-CLAUSE".
    LICENSE: str = "BSD-3-CLAUSE"

    #: Semantic version string, e.g. "1.0".
    VERSION: str

    #: Module reliability ranking
    RANK: int = EncoderRank.NORMAL

    #: External references as [type, url] pairs.
    REFERENCES: Sequence

    # Target specification

    #: Target architectures. Use the ARCH_* constants from
    #: core.payload.base for consistency. Use ["all"] to accept
    #: any architecture.
    ARCH: Sequence

    MAX_ITERATIONS: int = 256

    #: Optional prepended block of bytes to attach before the payload.
    #: Can be a static bytes object or a generator function that returns bytes.
    PREPEND_BUF: bytes | Callable

    #: Optional prepended block of bytes to attach before the payload.
    #: Can be a static bytes object or a generator function that returns bytes.
    DECODER: Mapping[str, str | int] = {
        "KeyOffset": 10,  # Byte offset in the decoder stub where the key should be patched
        "KeySize": 4,  # Number of bytes used for the key in the decoder stub
        "KeyPack": "<I",  # struct packing format for the key (e.g. little-endian unsigned int)
    }

    def decoder_key_offset(self):
        """Return the decoder key offset in bytes, if applicable."""
        return self.DECODER.get("KeyOffset", 10)

    def decoder_key_size(self):
        """Return the decoder key size in bytes, if applicable."""
        return int(self.DECODER.get("KeySize", 4))

    def decoder_key_pack(self):
        """Return the struct packing format string for the decoder key, if applicable."""
        return str(self.DECODER.get("KeyPack", "<I"))

    def decoder_block_size(self):
        """Return the block size in bytes for the encoding loop, if applicable."""
        block_size = self.DECODER.get("BlockSize", 0)

        if isinstance(block_size, int):
            return block_size

        return int(block_size)

    def init_state(self, state):
        """Initialize or reset any custom state parameters needed for the encoding lifecycle."""

        # Example of setting custom state parameters for decoder key management
        # Update the state with default decoder information
        state.decoder_key_offset = self.decoder_key_offset()
        state.decoder_key_size = self.decoder_key_size()
        state.decoder_key_pack = self.decoder_key_pack()
        state.decoder_stub = None

        # Reset key so find_key retry loops always begin from a clean seed.
        # Without this, a prior do_encode trial leaves state.key at its
        # post-encoding (rolled-forward) value, corrupting subsequent attempts.
        state.key = None

        # Restore the original buffer in case it was modified.
        state.buf = state.orig_buf

    def find_key(
        self,
        buf: bytes,
        badchars: bytes | AbstractSet[int],
        *args,
        **kwargs,
    ):
        """
        Finds a valid encryption key by filtering out explicitly known bad key bytes,
        randomly choosing from valid options, and verifying against bad characters.
        """
        _args, _kwargs = args, kwargs

        # Fetch the bad keys matrix. This should return a list of dictionaries/sets
        # representing bad byte values for each key index position.
        # e.g., [ {0x00: True}, {0x0a: True}, ... ]
        bad_keys = self.find_bad_keys(buf, badchars) if hasattr(self, "find_bad_keys") else [{} for _ in range(int(self.decoder_key_size()))]

        found = False
        key_bytes = [0] * int(self.decoder_key_size())

        # Ensure badchars is treated consistently as an integer lookup set
        badchars_set = set(badchars) if isinstance(badchars, bytes) else badchars

        # Keep chugging until we find a working key combination
        while not found:
            # Scan each byte position matching the decoder key size
            for index in range(int(self.decoder_key_size())):
                # Ruby: bad_keys[index].keys extracts the dictionary keys
                # We fetch the keys from the dictionary at this index (or treat it as a set)
                current_bad_set = set(bad_keys[index].keys()) if isinstance(bad_keys[index], dict) else set(bad_keys[index])

                # Subtract the bad values and leave the good ones
                good_keys = list(set(range(256)) - current_bad_set)

                # Was there anything left for this index?
                if len(good_keys) == 0:
                    # If a key index has 0 possible combinations left, encoding is impossible
                    return None

                # Set the appropriate key byte by picking a random choice from available pool
                key_bytes[index] = random.choice(good_keys)

            # Assume that we're going to rock this combination...
            found = True

            # Double check
            for byte in key_bytes:
                if byte in badchars_set:
                    found = False
                    break

            # If the key bytes are clean, pass them to the verification subroutine
            if found and hasattr(self, "find_key_verify"):
                found = self.find_key_verify(buf, key_bytes, badchars)

        # Do we have all the key bytes accounted for?
        if len(key_bytes) != self.decoder_key_size():
            return None

        # Convert the array of byte integers back into a single packed integer value
        if hasattr(self, "key_bytes_to_integer"):
            return self.key_bytes_to_integer(key_bytes)

        # Standard fallback: reconstruct standard little-endian integer from list of bytes
        return sum(b << (8 * i) for i, b in enumerate(key_bytes))

    def encode(self, raw_bytes: bytes, bad_bytes: frozenset[int], ctx: object | None = None) -> EncoderResult:
        """Runs the full encoding pipeline (state, key, hooks, and encoding)."""
        _ctx = ctx

        encoder_name = self._get_encoder_name()
        try:
            state = self._build_initial_state(raw_bytes, bad_bytes)
            self._apply_prepend_data(state, encoder_name)
            self._apply_init_state(state)
            self._resolve_key_if_needed(state, encoder_name)
            self._run_encode_pipeline(state)
            return self._build_success_result(state, encoder_name)

        except EncoderError:
            return self._handle_encode_error(encoder_name)

    def _get_encoder_name(self) -> str:
        """Returns encoder identifier used for logging and results."""
        return getattr(self, "NAME", self.__class__.__name__)

    def _build_initial_state(self, raw_bytes: bytes, bad_bytes: frozenset[int]):
        """Initializes EncoderState with input bytes and constraints."""
        return EncoderState(buf=raw_bytes, badchars=bad_bytes)

    def _apply_prepend_data(self, state, encoder_name: str) -> None:
        """Applies optional prepend buffer (static or callable)."""
        prepend_data: Callable | bytes = self.PREPEND_BUF

        try:
            if isinstance(prepend_data, Callable):
                prepend_data = prepend_data()

        except Exception as exc:
            raise RuntimeError(f"Error generating prepended data for {encoder_name}: {exc}") from exc

        if not isinstance(prepend_data, bytes):
            raise TypeError(f"PREPEND_BUF must be bytes or callable returning bytes, got {type(prepend_data)}")

        state.buf = prepend_data + state.buf

    def _apply_init_state(self, state) -> None:
        """Applies optional encoder-specific initialization hook."""
        if hasattr(self, "init_state"):
            self.init_state(state)

    def _resolve_key_if_needed(self, state, encoder_name: str) -> None:
        """Resolves encoding key if required by encoder configuration."""
        key_size = getattr(self, "decoder_key_size", None)

        if not (key_size and state.key is None):
            return

        key_finder = getattr(self, "find_key", getattr(self, "obtain_key", None))
        if key_finder is None:
            raise RuntimeError("No key discovery method available")

        resolved_key = key_finder(state.buf, state.badchars, state)

        if hasattr(state, "init_key"):
            state.init_key(resolved_key)
        else:
            state.key = resolved_key

        if state.key is None:
            raise RuntimeError(f"Failed to resolve key for {encoder_name}")

    def _run_encode_pipeline(self, state) -> None:
        """Executes encode hooks and core encoding logic."""
        state.encoded = b""

        if hasattr(self, "encode_begin"):
            self.encode_begin(state)

        self.do_encode(state)

        if hasattr(self, "encode_end"):
            self.encode_end(state)

    def _build_success_result(self, state, encoder_name: str) -> EncoderResult:
        """Builds successful encoding result object."""
        return EncoderResult(
            success=True,
            encoded_bytes=bytes(state.encoded),
            encoder_name=encoder_name,
            key_used=state.key,
        )

    def _handle_encode_error(self, encoder_name: str) -> EncoderResult:
        """Handles encoding failure and returns safe result."""
        return EncoderResult(
            success=False,
            encoded_bytes=b"",
            encoder_name=encoder_name,
            key_used=None,
        )

    def do_encode(self, state) -> bool:
        """Encode the payload, assemble the decoder stub, and validate the final output."""
        stub = self._build_decoder_stub(state)
        encoded = self._encode_payload_blocks(state)

        final_payload = bytes(stub + encoded)
        self._validate_badchars(
            final_payload,
            state.badchars,
            len(stub),
        )

        state.encoded = final_payload
        return True

    def _build_decoder_stub(
        self,
        state,
    ) -> bytearray:
        """Build and patch the decoder stub."""
        stub = bytearray(self.decoder_stub(state))

        key_offset = getattr(
            state,
            "decoder_key_offset",
            None,
        )

        if state.key is None or key_offset is None:
            return self._finalize_stub(
                state,
                stub,
            )

        key_size = getattr(
            state,
            "decoder_key_size",
            4,
        )

        key_pack = getattr(
            state,
            "decoder_key_pack",
            "<I",
        )

        real_key = self._resolve_decoder_key(state)

        packed_key = struct.pack(
            key_pack,
            int(real_key),
        )[:key_size]

        stub[key_offset : key_offset + key_size] = packed_key

        return stub

    def _finalize_stub(
        self,
        state,
        stub: bytearray,
    ) -> bytearray:
        """Apply optional stub finalization logic."""
        if hasattr(self, "encode_finalize_stub"):
            return bytearray(
                self.encode_finalize_stub(
                    state,
                    bytes(stub),
                )
            )

        return stub

    def _resolve_decoder_key(
        self,
        state,
    ) -> int:
        """Resolve the runtime decoder key."""
        if getattr(
            state,
            "context_encoding",
            False,
        ):
            return getattr(
                state,
                "context_address",
                0,
            )

        return state.key

    def _encode_payload_blocks(
        self,
        state,
    ) -> bytearray:
        """Encode the payload block-by-block."""
        encoded = bytearray()
        block_size = self.decoder_block_size()

        if not block_size:
            encoded.extend(
                self.encode_block(
                    state,
                    state.buf,
                )
            )
            return encoded

        for offset in range(
            0,
            len(state.buf),
            block_size,
        ):
            block = state.buf[offset : offset + block_size]
            if len(block) < block_size:
                block = block.ljust(
                    block_size,
                    b"\x00",
                )
            encoded.extend(
                self.encode_block(
                    state,
                    block,
                )
            )
        return encoded

    def _validate_badchars(
        self,
        payload: bytes,
        badchars,
        stub_size: int,
    ) -> None:
        """Validate that no bad characters exist in the final payload."""
        for index, byte_value in enumerate(payload):
            if byte_value in badchars:
                raise BadcharError(
                    index=index,
                    stub_size=stub_size,
                    message=(f"The {getattr(self, 'name', 'Shikata')} encoder generated a bad character layout."),
                )

    def obtain_key(self, buf, badchars, state):
        """Legacy fallback method name for find_key, if your framework variant requires it."""
        if self.DATASTORE.get("EnableContextEncoding"):
            return self.find_context_key(buf, badchars, state)

        return self.find_key(buf, badchars, state)

    def find_context_key(
        self,
        buf: bytes,
        badchars: bytes | AbstractSet[int],
        state,
    ) -> int:
        """Locate a compatible context-sensitive XOR key."""
        context_file = self._get_context_file()

        with open(context_file, "rb") as handle:
            result = self._search_context_records(
                handle,
                buf,
                badchars,
            )

        if result is None:
            raise LookupError(f"No context key could be located in {context_file}")

        address, key = result
        state.context_address = address
        state.context_encoding = True

        return key

    def _get_context_file(self) -> str:
        """Validate and return the configured context information file."""
        context_file = str(self.DATASTORE.get("ContextInformationFile"))

        if not os.path.exists(context_file):
            raise LookupError("A context information file must be specified when using context encoding.")
        return context_file

    def _search_context_records(
        self,
        handle,
        buf: bytes,
        badchars: bytes | AbstractSet[int],
    ) -> tuple[int, int] | None:
        """Search datastore records for a compatible key."""
        while True:
            record = self._read_context_record(handle)

            if record is None:
                return None

            base_address, data = record
            result = self._find_record_key(
                buf,
                badchars,
                base_address,
                data,
            )

            if result is not None:
                return result

    def _read_context_record(
        self,
        handle,
    ) -> tuple[int, bytes] | None:
        """Read a single datastore record."""
        header = handle.read(9)

        if len(header) < 9:
            return None

        _, base_address, size = struct.unpack(
            ">BII",
            header,
        )

        return base_address, handle.read(size)

    def _find_record_key(
        self,
        buf: bytes,
        badchars: bytes | AbstractSet[int],
        base_address: int,
        data: bytes,
    ) -> tuple[int, int] | None:
        """Search a datastore record for a valid key."""
        key_size = self.decoder_key_size()

        for offset in range(len(data) - key_size):
            key_bytes = data[offset : offset + key_size]

            if not self.find_key_verify(
                buf,
                key_bytes,
                badchars,
            ):
                continue

            address = base_address + offset

            if not self._is_valid_context_address(
                address,
                badchars,
            ):
                continue

            key = self.key_bytes_to_integer(key_bytes)

            return address, key
        return None

    def _is_valid_context_address(
        self,
        address: int,
        badchars: bytes | AbstractSet[int],
    ) -> bool:
        """
        Ensure the context address does not contain restricted bytes.
        """
        address_bytes = self.integer_to_key_bytes(address)

        return not any(byte in badchars for byte in address_bytes)

    def key_bytes_to_buffer(self, key_bytes):
        """
        Convert individual key bytes into a byte buffer.
        """
        # Ruby: key_bytes.pack('C*')[0, decoder_key_size]
        # Python: Converting list of ints directly to bytes, then slicing
        return bytes(key_bytes)[: self.decoder_key_size()]

    def key_bytes_to_integer(self, key_bytes):
        """
        Convert individual key bytes into a single integer based on the
        decoder's key size and packing requirements.
        """
        # Ruby: key_bytes_to_buffer(key_bytes).unpack(decoder_key_pack)[0]
        # Python: struct.unpack returns a tuple, so we fetch the first element [0]
        buffer = self.key_bytes_to_buffer(key_bytes)
        return struct.unpack(self.decoder_key_pack(), buffer)[0]

    def integer_to_key_bytes(self, integer):
        """
        Convert a single integer key value back into a byte array
        based on the decoder's key size and packing requirements.
        """
        # Ruby: [integer].pack(decoder_key_pack)[0, decoder_key_size]
        # Python: struct.pack returns bytes directly, so we slice it to the key size
        packed = struct.pack(self.decoder_key_pack(), int(integer))

        return list(packed[: self.decoder_key_size()])

    def find_bad_keys(self, buf, badchars):
        """
        Return a list of dictionaries representing bad key
        byte values for each key index position.
        """
        _buf, _badchars = buf, badchars

        return [{} for _ in range(self.decoder_key_size())]
