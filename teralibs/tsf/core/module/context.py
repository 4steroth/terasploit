import contextlib
import dataclasses
from dataclasses import field
from typing import Any

from teralibs.terasploit.framework.encoder.factory import EncoderFactory
from teralibs.terasploit.framework.payload.badchars import BadCharFilter
from teralibs.terasploit.framework.payload.sizer import PayloadSizeChecker
from teralibs.tsf.utils.path import ModuleIndex


@dataclasses.dataclass
class ContextDeps:
    """External dependencies injected into :class:ExploitContext."""

    job_id: str
    bus: Any
    datastore: Any
    payload_obj: Any | None = None
    module_obj: Any | None = None
    available_space: int | None = None


@dataclasses.dataclass
class _EncodingResult:
    """Intermediate result passed between the bad-char helper methods."""

    raw: bytes
    bad_bytes: frozenset[int] = field(default_factory=frozenset)
    enc_name: str | None = None
    arch: list[str] = field(default_factory=list)


class ExploitContext:
    """Runtime context injected into the exploit module's run() method."""

    _sizer = PayloadSizeChecker()
    session = None  # Set by the driver after a connection is opened.

    def __init__(self, deps):
        """
        Initialise the context.
        """
        self.job_id = deps.job_id
        self.bus = deps.bus
        self.datastore = deps.datastore
        self._payload = deps.payload_obj
        self._module = deps.module_obj
        self.available_space: int | None = deps.available_space

    def info(self, message):
        """Emit an informational log message."""
        self.bus.emit(self.job_id, "info", message)

    def success(self, message):
        """Emit a success log message."""
        self.bus.emit(self.job_id, "success", message)

    def warning(self, message):
        """Emit a warning log message."""
        self.bus.emit(self.job_id, "warning", message)

    def error(self, message):
        """Emit an error log message."""
        self.bus.emit(self.job_id, "error", message)

    def get_target(self):
        """Return the current set value for exploit target."""
        return self.datastore.get_value("TARGET")

    def get_option(self, name):
        """Return the current value of option *name*."""
        return self.datastore.get_value(name)

    def generate_payload(self):
        """Generate payload bytes and run the full validation pipeline."""
        if self._payload is None:
            raise RuntimeError("generate_payload() called but no payload is loaded.")

        raw = self._payload.generate(self)
        raw = self._run_badchar_pipeline(raw)
        self._run_size_check(raw)
        return raw

    def _resolve_option_cascade(self, key):
        """Return value for *key*."""
        return self.datastore.get_value(key)

    def _run_badchar_pipeline(self, raw):
        """Scan *raw* for bad characters and attempt encoding if needed."""
        ctx_enc_raw = self.datastore.get_value("EnableContextEncoding") or "false"
        context_encoding = str(ctx_enc_raw).lower().strip() in ("true", "yes", "1", "on")
        if context_encoding:
            arch = getattr(self._payload, "ARCH", []) or []

            enc_name = self._resolve_option_cascade("ENCODER") or None
            if enc_name:
                self.info(f"[ContextEnc] EnableContextEncoding is set - encoding with '{enc_name}'.")
                state = _EncodingResult(
                    raw=raw,
                    bad_bytes=frozenset(),
                    enc_name=enc_name,
                    arch=arch,
                )
                return self._encode_or_warn(state)

            self.warning(
                "[ContextEnc] EnableContextEncoding is set but no ENCODER "
                "is active - skipping context encoding. "
                "Load an encoder with 'set ENCODER <path>'."
            )

        raw_bc = self._resolve_option_cascade("BADCHARS")
        if not raw_bc:
            return raw

        bad_bytes = self._parse_badchars(raw_bc)
        if not bad_bytes:
            return raw

        scan = BadCharFilter.scan(raw, bad_bytes)
        if scan.clean:
            self.info("[BadChar] Payload is clean - no bad bytes found.")
            return raw

        self._report_badchar_hits(scan, raw, bad_bytes)
        state = _EncodingResult(
            raw=raw,
            bad_bytes=bad_bytes,
            enc_name=self._resolve_option_cascade("ENCODER") or None,
            arch=getattr(self._payload, "ARCH", []) or [],
        )
        return self._encode_or_warn(state)

    def _parse_badchars(self, raw_bc):
        """Parse *raw_bc* into a frozenset of bad bytes; warn on error."""
        try:
            return BadCharFilter.parse(raw_bc)

        except ValueError as exc:
            self.warning(f"[BadChar] Cannot parse BADCHARS: {exc}")
            return frozenset()

    def _report_badchar_hits(self, scan, raw, bad_bytes):
        """Emit all bad-character diagnostic messages for *scan*."""
        self.warning(f"[BadChar] Payload: {scan.summary()}")
        self.warning(BadCharFilter.format_hits(scan))
        self.warning("[BadChar] Byte map (xx = bad):\n" + BadCharFilter.byte_map(bad_bytes))
        self.warning("[BadChar] Hex dump:\n" + BadCharFilter.hex_dump(raw, bad_bytes))
        suggestions = EncoderFactory.suggest(bad_bytes, [])
        if suggestions:
            enc_list = ", ".join(f"{e.NAME} ({e.RANK.label()})" for e in suggestions)
            self.info(f"[BadChar] Compatible encoder(s): {enc_list}")

    def _encode_or_warn(self, state):
        """Attempt to encode *state.raw*; return clean bytes or the original."""
        enc_result = EncoderFactory.encode_payload(
            raw_bad_bytes=(state.raw, state.bad_bytes),
            encoder_name=state.enc_name,
            arch=state.arch,
            ctx=self,
        )

        if enc_result.success:
            self._report_encode_success(enc_result)
            return enc_result.encoded_bytes

        self._handle_encode_failure(enc_result)
        return state.raw

    def _report_encode_success(self, enc_result):
        """Log a success message after a clean encoding run."""
        key_used = enc_result.key_used
        key_info = f" (key=0x{key_used:02x})" if isinstance(key_used, int) else ""

        encoder_name = enc_result.encoder_name
        iterations = enc_result.iterations
        self.success(f"[BadChar] Encoded with '{encoder_name}' {key_info} in {iterations} iteration(s) - payload is now clean.")

    def _handle_encode_failure(self, enc_result):
        """Warn about encoding failure and raise if BADCHARS_STRICT is set."""
        error = enc_result.error
        self.warning(f"[BadChar] Encoding failed: {error}")

        strict_raw = self._resolve_option_cascade("BADCHARS_STRICT")
        if str(strict_raw).lower().strip() in ("true", "yes", "1", "on"):
            raise ValueError(
                "[BadChar] BADCHARS_STRICT is enabled and encoding failed - delivery aborted.  Adjust the BADCHARS set or choose a different payload."
            )

        self.warning("[BadChar] Continuing with unencoded payload (set BADCHARS_STRICT=true to block).")

    def _run_size_check(self, raw):
        """Run payload size validation and raise on failure."""
        size_result = self._sizer.check(raw_bytes=raw, payload_obj=self._payload, module_obj=self._module)
        self.info(f"Payload size: {size_result.summary()}")

        for warn in size_result.warnings:
            self.warning(warn)

        if not size_result.ok:
            for err in size_result.errors:
                self.error(err)
            raise ValueError(f"Payload size check failed ({size_result.generated:,} bytes). See above for details.")

    def _run_nop_sled_prepend(self, raw: bytes) -> bytes:
        """Prepend a NOP sled when ``NopSledSize`` is set and non-zero."""
        sled_size_raw = self.datastore.get_value("NopSledSize") or "0"

        sled_size = 0
        with contextlib.suppress(TypeError, ValueError):
            sled_size = int(sled_size_raw)

        if sled_size <= 0:
            return raw

        # Resolve bad-char set so the nop module can check compatibility.
        raw_bc = self._resolve_option_cascade("BADCHARS")
        badchars: frozenset[int] = self._parse_badchars(raw_bc) if raw_bc else frozenset()

        # Resolve the nop module to use.
        arch = getattr(self._payload, "ARCH", []) or []
        nop_module_name = self.datastore.get_value("NopSledModule") or None
        nop_inst = self._resolve_nop_module(nop_module_name, arch, badchars)
        if nop_inst is None:
            self.warning(
                f"[NopSled] Could not find a compatible NOP module for arch={arch} badchars={len(badchars)} byte(s) - skipping sled prepend."
            )
            return raw

        result = nop_inst.generate(sled_size, badchars)
        if not result.success:
            self.warning(f"[NopSled] Generation failed: {result.error} - skipping.")
            return raw

        self.info(f"[NopSled] Prepending {len(result.sled_bytes):,}-byte sled via '{result.nop_name}'.")
        return result.sled_bytes + raw

    def _resolve_nop_module(self, name: str | None, arch: list, badchars: frozenset[int]):
        """Return an instantiated Nops module or None."""
        idx = ModuleIndex()
        if name:
            with contextlib.suppress(Exception):
                mod = idx.load(name if "." in name else name.replace("/", "."))
                if mod:
                    return mod.TerasploitModule()
                raise RuntimeError("Nop module cannot load.")

            self.warning(f"[NopSled] Cannot load '{name}'")
            return None

        # Auto-select: prefer modules whose ARCH overlaps the payload's arch.
        arch_set = {a.lower() for a in arch} if arch else set()

        for module_name in sorted(idx.list_modules()):
            inst = None
            if not module_name.startswith("nop."):
                continue

            with contextlib.suppress(Exception):
                mod = idx.load(module_name)
                if mod:
                    inst = mod.TerasploitModule()
                raise RuntimeError("Nop module cannot load.")

            if not inst:
                continue

            # Arch compatibility: empty ARCH on module means "any".
            mod_arch = {a.lower() for a in (inst.ARCH or [])}
            if mod_arch and arch_set and mod_arch.isdisjoint(arch_set):
                continue

            if inst.can_avoid(badchars):
                return inst

        return None


@dataclasses.dataclass
class ExploitContextDeps:
    """Runtime context injected into exploit module check() methods."""

    job_id: Any
    module_obj: Any
    payload_obj: Any
    datastore: Any
    bus: Any
    available_space: int | None = None


@dataclasses.dataclass
class PostContextDeps:
    """Dependencies injected into PostContext."""

    job_id: Any
    bus: Any
    datastore: Any
    session: Any  # ShellSession instance resolved by _cmd_run


class PostContext:
    """Runtime context injected into post module run() methods."""

    def __init__(self, deps: PostContextDeps) -> None:
        self.job_id = deps.job_id
        self.bus = deps.bus
        self.datastore = deps.datastore
        self.session = deps.session

    # Logging - same surface as ExploitContext so module authors
    # need only one mental model for ctx logging calls.

    def info(self, message: str) -> None:
        """Emit an informational log message."""
        self.bus.emit(self.job_id, "info", message)

    def success(self, message: str) -> None:
        """Emit a success log message."""
        self.bus.emit(self.job_id, "success", message)

    def warning(self, message: str) -> None:
        """Emit a warning log message."""
        self.bus.emit(self.job_id, "warning", message)

    def error(self, message: str) -> None:
        """Emit an error log message."""
        self.bus.emit(self.job_id, "error", message)

    def get_option(self, name: str) -> object:
        """Return the current value of option *name*."""
        return self.datastore.get_value(name)


@dataclasses.dataclass
class AuxiliaryContextDeps:
    """Dependencies injected into PostContext."""

    job_id: Any
    bus: Any
    datastore: Any


class AuxiliaryContext:
    """Runtime context injected into post module run() methods."""

    def __init__(self, deps: AuxiliaryContextDeps) -> None:
        self.job_id = deps.job_id
        self.bus = deps.bus
        self.datastore = deps.datastore

    def info(self, message: str) -> None:
        """Emit an informational log message."""
        self.bus.emit(self.job_id, "info", message)

    def success(self, message: str) -> None:
        """Emit a success log message."""
        self.bus.emit(self.job_id, "success", message)

    def warning(self, message: str) -> None:
        """Emit a warning log message."""
        self.bus.emit(self.job_id, "warning", message)

    def error(self, message: str) -> None:
        """Emit an error log message."""
        self.bus.emit(self.job_id, "error", message)

    def get_option(self, name: str) -> object:
        """Return the current value of option *name*."""
        return self.datastore.get_value(name)
