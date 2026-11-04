import importlib.util
import os
import sys
import threading
from pathlib import Path
from typing import ClassVar

from teralibs.terasploit.framework.payload.badchars import BadCharFilter
from teralibs.tsf.base.encoder import Encoder, EncoderResult


class EncoderFactory:
    """Global registry and pipeline for Terasploit payload encoders."""

    # Class-level registry shared across all callers.
    _registry: ClassVar = []
    _dotted_map: ClassVar = {}  # dotted-path -> Encoder instance

    _encoder_dir_mtime = 0.0
    _lock = threading.Lock()

    # Discovery

    @classmethod
    def reset(cls):
        """Clear all registered encoders and reset discovery state."""
        cls._registry.clear()
        cls._dotted_map.clear()
        cls._encoder_dir_mtime = 0.0

    @classmethod
    def _encoder_dir(cls):
        """Return the absolute path to the modules/encoder/ directory."""
        # __file__ = teralibs/terasploit/framework/encoder/encoder_factory.py
        # .parent   = teralibs/terasploit/framework/encoder/
        # .parent   = teralibs/terasploit/framework/
        # .parent   = teralibs/terasploit/
        # .parent   = teralibs/
        # .parent   = <project_root>/
        here = Path(__file__).resolve().parent  # teralibs/terasploit/framework/encoder/
        root = here.parent.parent.parent.parent  # project root
        return root / "modules" / "encoder"

    @classmethod
    def _discover(cls, force=False):
        """Scan modules/encoder/ and register any new encoder modules."""
        enc_dir = cls._encoder_dir()
        try:
            current_mtime = os.path.getmtime(str(enc_dir))
        except OSError:
            # Encoder directory does not exist yet - nothing to discover.
            return

        # Skip re-scan when mtime is unchanged and force is False.
        if not force and current_mtime == cls._encoder_dir_mtime:
            return
        cls._encoder_dir_mtime = current_mtime

        for filepath in sorted(enc_dir.rglob("*.py")):
            if filepath.name == "__init__.py":
                continue

            # Build a unique dotted module name from the file's path
            # relative to the encoder directory's parent (modules/).
            relative = filepath.relative_to(enc_dir.parent).with_suffix("")
            dotted = "encoder." + ".".join(relative.parts[1:])

            # Skip modules already registered from a previous scan.
            if dotted in cls._dotted_map:
                continue

            mod_obj = cls._load_file(dotted, str(filepath))
            if mod_obj is None:
                continue

            # Every encoder file must expose a TerasploitModule class.
            klass = getattr(mod_obj, "TerasploitModule", None)
            if klass is None:
                continue
            if not (isinstance(klass, type) and issubclass(klass, Encoder)):
                continue

            try:
                # Instantiate the encoder class - bad __init__ signatures
                # raise TypeError, missing attributes raise AttributeError.
                # pylint: disable=not-callable
                instance = klass()
            except TypeError, AttributeError, ImportError, ValueError:
                continue

            cls._register_instance(dotted, instance)

    @staticmethod
    def _load_file(module_name, filepath):
        """Load a Python file as a module and return the module object."""
        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec is None or spec.loader is None:
                return None
            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)
            return mod
        except ImportError, AttributeError, SyntaxError, OSError:
            # ImportError/AttributeError: bad imports inside the encoder.
            # SyntaxError: the file has a syntax error.
            # OSError: the file disappeared between discovery and load.
            return None

    @classmethod
    def _register_instance(cls, dotted, instance):
        """Add *instance* to the dotted-path map and the sorted registry."""
        with cls._lock:
            cls._dotted_map[dotted] = instance
            # Guard against duplicate NAME registrations (e.g. after force re-scan).
            if any(e.NAME == instance.NAME for e in cls._registry):
                return
            cls._registry.append(instance)
            # Keep registry sorted by rank descending so suggest() / pipeline
            # iterate highest-quality encoders first.
            cls._registry.sort(key=lambda e: int(e.RANK), reverse=True)

    # Public registry management

    @classmethod
    def register(cls, encoder):
        """Manually register an encoder instance outside of file discovery."""
        cls._discover()
        cls._register_instance("_manual." + encoder.NAME, encoder)

    @classmethod
    def all_encoders(cls):
        """Return a copy of the registry (all discovered encoders, ranked)."""
        cls._discover()
        return list(cls._registry)

    @classmethod
    def get(cls, name):
        """Look up an encoder by NAME or dotted path."""
        cls._discover()
        # Normalise separators so callers can use "/" or "." interchangeably.
        dotted_name = name.replace("/", ".").strip(".")

        for enc in cls._registry:
            if name == enc.NAME or name.replace(".", "/") == enc.NAME:
                return enc

        if dotted_name in cls._dotted_map:
            return cls._dotted_map[dotted_name]

        for path, enc in cls._dotted_map.items():
            if path.endswith(dotted_name):
                return enc

        return None

    @classmethod
    def get_by_dotted(cls, dotted):
        """Return the encoder registered under the exact *dotted* key."""
        cls._discover()
        return cls._dotted_map.get(dotted)

    @classmethod
    def dotted_paths(cls):
        """Return a sorted list of all registered dotted-path keys."""
        cls._discover()
        return sorted(cls._dotted_map.keys())

    # Selection

    @classmethod
    def suggest(
        cls,
        bad_bytes,
        arch=None,
    ):
        """Return compatible encoders sorted by rank (highest first)."""
        cls._discover()
        candidates = []
        for enc in cls._registry:
            if enc.ARCH:
                # Encoder requires a specific architecture.
                if not arch:
                    continue
                if not any(a in enc.ARCH for a in arch):
                    continue
            if enc.can_avoid(bad_bytes):
                candidates.append(enc)
        return candidates

    # Encoding pipeline

    @classmethod
    def encode_payload(
        cls,
        raw_bad_bytes,
        encoder_name=None,
        arch=None,
        ctx=None,
    ):
        """Run the encoding pipeline and return the best clean result."""
        cls._discover()

        raw_bytes, bad_bytes = raw_bad_bytes

        # If there are no bad bytes AND no specific encoder was requested,
        # return the raw payload unchanged - nothing to do.
        # When the user explicitly names an encoder (e.g. -e shikata_ga_nai -i 3)
        # we must NOT short-circuit here; they want the encoding to actually run.
        if not bad_bytes and not encoder_name:
            return EncoderResult(
                success=True,
                encoded_bytes=raw_bytes,
                encoder_name="none",
                key_used=None,
                iterations=0,
            )

        # Named encoder requested - try it exclusively.
        if encoder_name:
            enc = cls.get(encoder_name)
            if enc is None:
                available = ", ".join(e.NAME for e in cls._registry)
                return EncoderResult(
                    success=False,
                    encoded_bytes=b"",
                    encoder_name=encoder_name,
                    error=(f"Unknown encoder {encoder_name!r}.  Available: {available}"),
                )
            result = enc.encode(raw_bytes, bad_bytes, ctx)
            if result.success:
                result = cls._verify(result, bad_bytes)
            return result

        # Auto-select from ranked candidates.
        candidates = cls.suggest(bad_bytes, arch)
        if not candidates:
            return EncoderResult(
                success=False,
                encoded_bytes=b"",
                encoder_name="none",
                error="No compatible encoder found in the registry.",
            )

        last_error = ""
        for enc in candidates:
            result = enc.encode(raw_bytes, bad_bytes, ctx)
            if not result.success:
                last_error = result.error
                continue
            result = cls._verify(result, bad_bytes)
            if result.success:
                return result
            last_error = result.error

        return EncoderResult(
            success=False,
            encoded_bytes=b"",
            encoder_name="none",
            error=(f"Pipeline exhausted {len(candidates)} encoder(s).  Last error: {last_error}"),
        )

    # Internal helpers

    @staticmethod
    def _verify(result, bad_bytes):
        """Post-encode verification: re-scan the encoded bytes for bad bytes."""
        if not BadCharFilter.is_clean(result.encoded_bytes, bad_bytes):
            return EncoderResult(
                success=False,
                encoded_bytes=b"",
                encoder_name=result.encoder_name,
                key_used=result.key_used,
                iterations=result.iterations,
                error=(f"Post-encode verification failed for '{result.encoder_name}' (encoder reported success but output is still dirty)."),
            )
        return result
