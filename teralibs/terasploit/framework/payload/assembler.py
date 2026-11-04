import importlib
import struct

from teralibs.terasploit.framework.encoder.factory import EncoderFactory
from teralibs.terasploit.framework.payload.badchars import BadCharFilter
from teralibs.terasploit.framework.payload.sizer import PayloadSizeChecker
from teralibs.tsf.utils.exception import DatastoreAccessError


# Root Python package path for stage modules.
_STAGE_MODULE_ROOT = "modules.payload.stages"

# Stages larger than this threshold produce a size warning in the log.
_LARGE_STAGE_THRESHOLD = 512 * 1024  # 512 KiB

# Module-level sizer instance reused across all StageAssembler instances.
_sizer = PayloadSizeChecker()


class StageAssembler:
    """Loads a companion stage module and delivers its bytes over a socket."""

    def __init__(self, stage_path, length_prefix=False):
        """Initialise a StageAssembler for the given *stage_path*."""
        self._stage_path = stage_path

        # Default length prefixing behavior is determined by stage OS family conventions:
        self._length_prefix = length_prefix

        # Windows stages typically expect length prefixing by default,
        # since that's a common convention for Windows shellcode and staged payloads.
        if stage_path.lower().startswith("windows"):
            self._length_prefix = True

        # Linux/Unix stages typically do not use length prefixing by default
        # since it's less common for staged payloads on Unix-like platforms
        # and in cross-platform contexts.
        elif stage_path.split(".")[0].lower() in ("linux", "unix"):
            self._length_prefix = False

    # Public API

    def load_stage(self):
        """Import and instantiate the stage module."""
        full_path = f"{_STAGE_MODULE_ROOT}.{self._stage_path}"
        mod = importlib.import_module(full_path)
        return mod.TerasploitModule()

    def validate(self):
        """Pre-flight check: verify the stage module is importable."""
        self.load_stage()
        return True

    def deliver(self, sock, ctx) -> bool:
        """Generate, (optionally) encode, scan for bad chars, and send the stage."""
        stage_obj = self._load_and_build_stage(ctx)
        if stage_obj is None:
            return False

        stage_bytes = self._generate_stage_payload(stage_obj, ctx)
        if stage_bytes is None:
            return False

        if not self._validate_stage_size(stage_bytes, stage_obj, ctx):
            return False

        stage_bytes = self._apply_encoding_pipeline(stage_bytes, stage_obj, ctx)
        if stage_bytes is None:
            return False

        payload = self._finalize_payload_stream(stage_bytes)
        return self._transmit_payload(sock, payload, len(stage_bytes), ctx)

    def _load_and_build_stage(self, ctx):
        """Loads the defined stage component target; logs and returns None on error."""
        try:
            return self.load_stage()
        except (ImportError, AttributeError) as exc:
            ctx.error(f"Cannot load stage '{self._stage_path}': {exc}")
            return None

    def _generate_stage_payload(self, stage_obj, ctx) -> bytes | bytearray | None:
        """Invokes generation hooks to build raw binary material from the stage module."""
        try:
            stage_bytes = stage_obj.generate_stage(ctx)

        except (NotImplementedError, TypeError, ValueError, OSError) as exc:
            ctx.error(f"Stage generation failed: {exc}")
            return None

        if not isinstance(stage_bytes, (bytes, bytearray)):
            ctx.error(f"Stage generate_stage() returned {type(stage_bytes).__name__!r} instead of bytes - aborting delivery.")
            return None

        return stage_bytes

    def _validate_stage_size(self, stage_bytes: bytes | bytearray, stage_obj, ctx) -> bool:
        """Runs validation routines to verify layout sizes fit operational parameters."""
        result = _sizer.check(
            raw_bytes=stage_bytes,
            payload_obj=stage_obj,
            module_obj=None,
        )
        ctx.info(f"Stage size: {result.summary()}")

        for warn in result.warnings:
            ctx.warning(warn)

        if not result.ok:
            for err in result.errors:
                ctx.error(err)
            ctx.error("Stage size check failed - aborting delivery.")
            return False

        size = len(stage_bytes)
        if size > _LARGE_STAGE_THRESHOLD:
            ctx.warning(f"Stage is {size:,} bytes - larger than the recommended {_LARGE_STAGE_THRESHOLD:,} bytes.")
        return True

    def _apply_encoding_pipeline(self, stage_bytes: bytes | bytearray, stage_obj, ctx) -> bytes | bytearray | None:
        """Processes proactive encoders and performs automated evasion scanning."""
        # Check active settings scopes for evasion optimization requirements
        enable_enc_raw = (
            self._get_opt(ctx, "EnableStageEncoding", scope="payload_advanced")
            or self._get_opt(ctx, "EnableStageEncoding", scope="payload")
            or self._get_opt(ctx, "EnableStageEncoding")
            or ""
        )

        if str(enable_enc_raw).lower().strip() in ("true", "yes", "1", "on"):
            enc_ok, stage_bytes = self._stage_encode(stage_bytes, ctx, stage_obj)
            if not enc_ok:
                return None

        # Execute reactive constraints filtering check
        bc_ok, stage_bytes = self._badchar_check(stage_bytes, ctx, label="Stage", module_obj=stage_obj)
        if not bc_ok:
            return None

        return stage_bytes

    def _finalize_payload_stream(self, stage_bytes: bytes | bytearray) -> bytes:
        """Appends custom serialization components, such as big-endian length prefixes."""
        size = len(stage_bytes)
        if self._length_prefix and stage_bytes:
            # Default to big-endian length prefixing for non-Windows stages,
            # since that's a common convention for staged payloads on Unix-like
            # platforms and in cross-platform contexts.
            prefix = struct.pack(">I", size)

            # We use little-endian length prefixing for Windows stages by default, since
            # that's the most common format for Windows shellcode and stage payloads.
            if self._stage_path.lower().startswith("windows"):
                prefix = struct.pack("<I", size)

            # We seperated thisly in case we want different prefixing logic
            # for different OS families in the future, but for now we'll
            # just use big-endian for non-Windows stages.
            if self._stage_path.split(".")[0].lower() in ("linux", "unix"):
                prefix = struct.pack(">I", size)

            return prefix + bytes(stage_bytes)
        return bytes(stage_bytes)

    def _transmit_payload(self, sock, payload: bytes, original_size: int, ctx) -> bool:
        """Handles physical socket operation transport write calls."""
        ctx.info(f"Sending stage '{self._stage_path}'...")
        try:
            if payload:
                sock.sendall(payload)
            ctx.success(f"Stage sent ({original_size:,} bytes).")
            return True

        except OSError as exc:
            ctx.error(f"Stage delivery failed (socket error): {exc}")
            return False
        except (RuntimeError, ValueError) as exc:
            ctx.error(f"Stage delivery failed (unexpected error): {exc}")
            return False

    @staticmethod
    def _get_opt(ctx, name, scope=None):
        """Safe datastore read; returns empty string on any error."""
        try:
            val = ctx.datastore.get(name, scope=scope)
            return str(val).strip() if val else ""

        except DatastoreAccessError:
            return ""

    @staticmethod
    def _stage_encode(
        raw_bytes,
        ctx,
        module_obj=None,
    ):
        """Proactively encode the stage for IDS evasion."""

        enc_name = (
            ctx.datastore.get("StageEncoder", scope="payload_advanced")
            or ctx.datastore.get("StageEncoder", scope="payload")
            or ctx.datastore.get("StageEncoder")
            or getattr(module_obj, "ENCODER", None)
            or None
        )

        arch = getattr(module_obj, "ARCH", []) or []

        saved_regs_raw = (
            ctx.datastore.get("StageEncoderSavedRegisters", scope="payload_advanced") or ctx.datastore.get("StageEncoderSavedRegisters") or ""
        )
        if saved_regs_raw:
            ctx.info(f"[StageEncode] Saved registers hint: {saved_regs_raw}")

        # Use an empty frozenset so EncoderFactory doesn't filter by bad bytes -
        # we're encoding for evasion, not bad-char avoidance.
        enc_result = EncoderFactory.encode_payload(
            raw_bad_bytes=(raw_bytes, frozenset()),
            encoder_name=enc_name,
            arch=arch,
            ctx=ctx,
        )

        if enc_result.success:
            key_info = f" (key=0x{enc_result.key_used:02x})" if isinstance(enc_result.key_used, int) else ""
            ctx.success(f"[StageEncode] Stage encoded with '{enc_result.encoder_name}'{key_info} ({len(enc_result.encoded_bytes):,} bytes).")
            return True, enc_result.encoded_bytes

        ctx.warning(f"[StageEncode] EnableStageEncoding is set but encoding failed: {enc_result.error} - delivering unencoded stage.")
        return True, raw_bytes  # soft failure: warn but continue

    @staticmethod
    def _badchar_check(
        raw_bytes,
        ctx,
        label="Payload",
        module_obj=None,
    ):
        """Scan *raw_bytes* for bad characters and attempt automatic encoding."""
        # Resolve bad-char constraints and validate early
        bad_bytes = StageAssembler.resolve_bad_bytes(ctx, module_obj)
        if not bad_bytes:
            return True, raw_bytes

        scan = BadCharFilter.scan(raw_bytes, bad_bytes)
        if scan.clean:
            ctx.info(f"[BadChar] {label} is clean - no bad bytes found.")
            return True, raw_bytes

        # Log bad character hits for the operator
        ctx.warning(f"[BadChar] {label}: {scan.summary()}")
        ctx.warning(BadCharFilter.format_hits(scan))
        ctx.warning("[BadChar] Byte map (xx = bad):\n" + BadCharFilter.byte_map(bad_bytes))
        ctx.warning("[BadChar] Hex dump:\n" + BadCharFilter.hex_dump(raw_bytes, bad_bytes))

        # Handle reactive encoding pipeline
        success, encoded_bytes = StageAssembler.execute_encoder_pipeline(raw_bytes, bad_bytes, ctx, module_obj, label)
        if success:
            return True, encoded_bytes

        # Handle fallback enforcement if encoding fails
        return StageAssembler.handle_strict_enforcement(raw_bytes, ctx, label)

    @staticmethod
    def resolve_bad_bytes(ctx, module_obj) -> frozenset | None:
        """Resolves and parses configured BADCHARS constraints."""
        raw_badchars = (
            ctx.datastore.get("BADCHARS", scope="payload_advanced")
            or ctx.datastore.get("BADCHARS", scope="payload")
            or ctx.datastore.get("BADCHARS")
            or getattr(module_obj, "BADCHARS", "")
            or ""
        )
        if not raw_badchars:
            return None

        try:
            return BadCharFilter.parse(raw_badchars)
        except ValueError as exc:
            ctx.warning(f"[BadChar] Could not parse BADCHARS value: {exc}")
            return None

    @staticmethod
    def execute_encoder_pipeline(raw_bytes, bad_bytes, ctx, module_obj, label) -> tuple[bool, bytes | bytearray]:
        """Attempts payload encoding and reports suggestions/results."""
        enc_name = (
            ctx.datastore.get("ENCODER", scope="payload_advanced")
            or ctx.datastore.get("ENCODER", scope="payload")
            or ctx.datastore.get("ENCODER")
            or getattr(module_obj, "ENCODER", None)
            or None
        )
        arch = getattr(module_obj, "ARCH", []) or []

        suggestions = EncoderFactory.suggest(bad_bytes, arch)
        if suggestions:
            enc_list = ", ".join(f"{e.NAME} ({e.RANK.label()})" for e in suggestions)
            ctx.info(f"[BadChar] Compatible encoder(s): {enc_list}")

        enc_result = EncoderFactory.encode_payload(
            raw_bad_bytes=(raw_bytes, bad_bytes),
            encoder_name=enc_name,
            arch=arch,
            ctx=ctx,
        )

        if enc_result.success:
            key_info = f" (key=0x{enc_result.key_used:02x})" if isinstance(enc_result.key_used, int) else ""
            ctx.success(f"[BadChar] {label} encoded with '{enc_result.encoder_name}'{key_info} in {enc_result.iterations} iteration(s) - now clean.")
            return True, enc_result.encoded_bytes

        ctx.warning(f"[BadChar] Encoding failed: {enc_result.error}")
        return False, raw_bytes

    @staticmethod
    def handle_strict_enforcement(raw_bytes, ctx, label) -> tuple[bool, bytes | bytearray]:
        """Validates configuration strictness rules when an unencoded payload persists."""
        strict_raw = (
            ctx.datastore.get("BADCHARS_STRICT", scope="payload_advanced")
            or ctx.datastore.get("BADCHARS_STRICT", scope="payload")
            or ctx.datastore.get("BADCHARS_STRICT")
            or ""
        )
        if str(strict_raw).lower().strip() in ("true", "yes", "1", "on"):
            ctx.error(
                f"[BadChar] BADCHARS_STRICT is enabled - aborting {label.lower()} delivery.  Adjust BADCHARS or choose a different payload/encoder."
            )
            return False, raw_bytes

        ctx.warning("[BadChar] Continuing with unencoded payload (set BADCHARS_STRICT=true to block).")
        return True, raw_bytes
