import contextlib
import dataclasses
import os
import random
import struct
from collections.abc import Callable, Mapping, Sequence
from enum import IntEnum
from typing import Any

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


__all__ = [
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
    "EncoderState",
]


class EncoderRank(IntEnum):
    """Numeric rank for encoder quality, used to sort the selection pipeline."""

    MANUAL = 0
    LOW = 100
    NORMAL = 200
    GOOD = 300
    GREAT = 400
    EXCELLENT = 500

    def label(self) -> str:
        """Return the capitalised rank name (e.g. 'Excellent')."""
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


class Encoder(Base):
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

    #: Module reliability ranking.
    RANK: int = EncoderRank.NORMAL

    #: External references as [type, url] pairs.
    REFERENCES: Sequence

    #: Target architectures. Use the ARCH_* constants for consistency.
    #: Use ["all"] to accept any architecture.
    ARCH: Sequence

    MAX_ITERATIONS: int = 256

    #: Optional bytes to prepend before the payload; may be static or callable.
    PREPEND_BUF: Any

    #: Decoder stub configuration: key offset, key size, and struct pack format.
    DECODER: Mapping[str, str | int] = {
        "KeyOffset": 10,
        "KeySize": 4,
        "KeyPack": "<I",
    }

    def decoder_key_offset(self):
        """Return the byte offset in the stub where the key is patched."""
        return self.DECODER.get("KeyOffset", 10)

    def decoder_key_size(self):
        """Return the key size in bytes."""
        return int(self.DECODER.get("KeySize", 4))

    def decoder_key_pack(self):
        """Return the struct packing format string for the decoder key."""
        return str(self.DECODER.get("KeyPack", "<I"))

    def decoder_block_size(self):
        """Return the encoding loop block size in bytes."""
        block_size = self.DECODER.get("BlockSize", 0)
        return block_size if isinstance(block_size, int) else int(block_size)

    def init_state(self, state):
        """Initialise encoder state parameters for the encoding lifecycle."""
        state.decoder_key_offset = self.decoder_key_offset()
        state.decoder_key_size = self.decoder_key_size()
        state.decoder_key_pack = self.decoder_key_pack()
        state.decoder_stub = None

        # Reset so find_key retry loops always start from a clean seed;
        # a prior do_encode trial leaves state.key at its rolled-forward value.
        state.key = None

        state.buf = state.orig_buf

    def find_key(self, buf, badchars, *args, **kwargs):
        """Find a valid encoding key by excluding known bad byte values."""
        _args, _kwargs = args, kwargs

        key_size = int(self.decoder_key_size())
        bad_keys = self.find_bad_keys(buf, badchars) if hasattr(self, "find_bad_keys") else [{} for _ in range(key_size)]

        badchars_set = set(badchars) if isinstance(badchars, bytes) else badchars
        key_bytes = [0] * key_size
        found = False

        while not found:
            for index in range(key_size):
                current_bad = set(bad_keys[index].keys()) if isinstance(bad_keys[index], dict) else set(bad_keys[index])
                good_keys = list(set(range(256)) - current_bad)
                if not good_keys:
                    return None
                key_bytes[index] = random.choice(good_keys)

            found = not any(b in badchars_set for b in key_bytes)

            if found and hasattr(self, "find_key_verify"):
                found = self.find_key_verify(buf, key_bytes, badchars)

        if len(key_bytes) != key_size:
            return None

        if hasattr(self, "key_bytes_to_integer"):
            return self.key_bytes_to_integer(key_bytes)

        return sum(b << (8 * i) for i, b in enumerate(key_bytes))

    def encode(self, raw_bytes, bad_bytes, ctx):
        """Run the full encoding pipeline: state, key, hooks, and encode."""
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

    def _get_encoder_name(self):
        """Return the encoder identifier used for logging and results."""
        return getattr(self, "NAME", self.__class__.__name__)

    def _build_initial_state(self, raw_bytes, bad_bytes):
        """Construct and return the initial EncoderState."""
        state = EncoderState()
        state.buf = raw_bytes
        state.badchars = bad_bytes
        return state

    def _apply_prepend_data(self, state, encoder_name):
        """Apply the optional prepend buffer (static bytes or callable)."""
        prepend_data = b""
        with contextlib.suppress(Exception):
            prepend_data = self.PREPEND_BUF

        try:
            if isinstance(prepend_data, Callable):
                prepend_data = prepend_data()
        except Exception as exc:
            raise RuntimeError(f"Error generating prepended data for {encoder_name}: {exc}") from exc

        if not isinstance(prepend_data, bytes):
            raise TypeError(f"PREPEND_BUF must be bytes or callable returning bytes, got {type(prepend_data)}")

        state.buf = prepend_data + state.buf

    def _apply_init_state(self, state):
        """Apply the encoder-specific initialisation hook if present."""
        if hasattr(self, "init_state"):
            self.init_state(state)

    def _resolve_key_if_needed(self, state, encoder_name):
        """Resolve the encoding key when one is required but not yet set."""
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

    def _run_encode_pipeline(self, state):
        """Execute encode hooks and core encoding logic."""
        state.encoded = b""

        if hasattr(self, "encode_begin"):
            self.encode_begin(state)

        self.do_encode(state)

        if hasattr(self, "encode_end"):
            self.encode_end(state)

    def _build_success_result(self, state, encoder_name):
        """Build and return a successful EncoderResult."""
        return EncoderResult(
            success=True,
            encoded_bytes=bytes(state.encoded),
            encoder_name=encoder_name,
            key_used=state.key,
        )

    def _handle_encode_error(self, encoder_name):
        """Build and return a failed EncoderResult."""
        return EncoderResult(
            success=False,
            encoded_bytes=b"",
            encoder_name=encoder_name,
            key_used=None,
        )

    def do_encode(self, state):
        """Encode payload, assemble stub, and validate for bad characters."""
        stub = self._build_decoder_stub(state)
        encoded = self._encode_payload_blocks(state)

        final_payload = bytes(stub + encoded)
        self._validate_badchars(final_payload, state.badchars, len(stub))

        state.encoded = final_payload
        return True

    def _build_decoder_stub(self, state):
        """Build and patch the decoder stub with the resolved key."""
        stub = bytearray(self.decoder_stub(state))

        key_offset = getattr(state, "decoder_key_offset", None)
        if state.key is None or key_offset is None:
            return self._finalize_stub(state, stub)

        key_size = getattr(state, "decoder_key_size", 4)
        key_pack = getattr(state, "decoder_key_pack", "<I")
        real_key = self._resolve_decoder_key(state)
        packed_key = struct.pack(key_pack, int(real_key))[:key_size]
        stub[key_offset : key_offset + key_size] = packed_key

        return stub

    def _finalize_stub(self, state, stub):
        """Apply optional stub finalisation logic if the hook is present."""
        if hasattr(self, "encode_finalize_stub"):
            return bytearray(self.encode_finalize_stub(state, bytes(stub)))
        return stub

    def _resolve_decoder_key(self, state):
        """Return the context address or the raw key depending on encoding mode."""
        if getattr(state, "context_encoding", False):
            return getattr(state, "context_address", 0)
        return state.key

    def _encode_payload_blocks(self, state):
        """Encode the payload buffer in block-sized chunks."""
        encoded = bytearray()
        block_size = self.decoder_block_size()

        if not block_size:
            encoded.extend(self.encode_block(state, state.buf))
            return encoded

        for offset in range(0, len(state.buf), block_size):
            block = state.buf[offset : offset + block_size]
            if len(block) < block_size:
                block = block.ljust(block_size, b"\x00")
            encoded.extend(self.encode_block(state, block))

        return encoded

    def _validate_badchars(self, payload, badchars, stub_size):
        """Raise BadcharError if any restricted byte appears in the payload."""
        for index, byte_value in enumerate(payload):
            if byte_value in badchars:
                raise BadcharError(
                    index=index,
                    stub_size=stub_size,
                    message=f"The {getattr(self, 'NAME', 'selected')} encoder generated a bad character layout.",
                )

    def obtain_key(self, buf, badchars, state):
        """Legacy alias for find_key; supports the context-encoding path."""
        if self.DATASTORE["EnableContextEncoding"]:
            return self.find_context_key(buf, badchars, state)
        return self.find_key(buf, badchars, state)

    def find_context_key(self, buf, badchars, state):
        """Locate a compatible context-sensitive XOR key from the data file."""
        context_file = self._get_context_file()
        with open(context_file, "rb") as handle:
            result = self._search_context_records(handle, buf, badchars)

        if result is None:
            raise LookupError(f"No context key could be located in {context_file}")

        address, key = result
        state.context_address = address
        state.context_encoding = True
        return key

    def _get_context_file(self):
        """Validate and return the configured context information file path."""
        context_file = str(self.DATASTORE["ContextInformationFile"])
        if not os.path.exists(context_file):
            raise LookupError("A context information file must be specified when using context encoding.")
        return context_file

    def _search_context_records(self, handle, buf, badchars):
        """Scan all datastore records until a compatible key is found."""
        while True:
            record = self._read_context_record(handle)
            if record is None:
                return None

            base_address, data = record
            result = self._find_record_key(buf, badchars, base_address, data)
            if result is not None:
                return result

    def _read_context_record(self, handle):
        """Read and unpack one datastore record; return None on EOF."""
        header = handle.read(9)
        if len(header) < 9:
            return None

        _, base_address, size = struct.unpack(">BII", header)
        return base_address, handle.read(size)

    def _find_record_key(self, buf, badchars, base_address, data):
        """Return (address, key) for the first valid key in a record, or None."""
        key_size = self.decoder_key_size()

        for offset in range(len(data) - key_size):
            key_bytes = data[offset : offset + key_size]
            if not self.find_key_verify(buf, key_bytes, badchars):
                continue

            address = base_address + offset
            if not self._is_valid_context_address(address, badchars):
                continue

            return address, self.key_bytes_to_integer(key_bytes)

        return None

    def _is_valid_context_address(self, address, badchars):
        """Return True when no byte of address appears in badchars."""
        return not any(b in badchars for b in self.integer_to_key_bytes(address))

    def key_bytes_to_buffer(self, key_bytes):
        """Convert a key byte list into a bytes buffer of decoder_key_size."""
        return bytes(key_bytes)[: self.decoder_key_size()]

    def key_bytes_to_integer(self, key_bytes):
        """Pack key bytes into an integer using the decoder's key format."""
        return struct.unpack(self.decoder_key_pack(), self.key_bytes_to_buffer(key_bytes))[0]

    def integer_to_key_bytes(self, integer):
        """Unpack an integer key into a list of bytes using decoder format."""
        packed = struct.pack(self.decoder_key_pack(), int(integer))
        return list(packed[: self.decoder_key_size()])

    def find_bad_keys(self, buf, badchars):
        """Return per-index bad byte sets for key positions; empty by default."""
        _buf, _badchars = buf, badchars
        return [{} for _ in range(self.decoder_key_size())]

    def has_badchars(self, buf, badchars):
        """Return the index of the first bad character in buf, or None."""
        for badchar in badchars:
            idx = buf.find(bytes([badchar]))
            if idx != -1:
                return idx
        return None

    def find_key_verify(self, buf, key_bytes, badchars):
        """Verify that key_bytes do not produce bad characters in buf."""
        _buf, _key_bytes, _badchars = buf, key_bytes, badchars
        return True

    def encode_begin(self, state):
        """Hook called immediately before encoding begins."""
        _state = state

    def encode_end(self, state):
        """Hook called immediately after encoding completes."""
        _state = state

    def encode_finalize_stub(self, state, stub):
        """Override to finalise the decoder stub after key selection."""
        _state = state
        return stub

    def encode_block(self, state, block):
        """Encode one block of bytes; override in each encoder subclass."""
        _state = state
        return block

    def decoder_stub(self, state) -> bytes:
        """Return the decoder stub bytes for the current encoder state."""
        _state = state
        return b""

    def can_avoid(self, bad_bytes):
        """Return True if this encoder might be able to avoid bad_bytes."""
        _bad_bytes = bad_bytes
        return True
