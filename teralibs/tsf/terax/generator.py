import sys
import traceback
from datetime import datetime

from teralibs.terasploit.framework.payload.badchars import BadCharFilter
from teralibs.terasploit.framework.services.printf import (
    error,
    info,
    print_line,
    set_timestamp,
    set_verbose,
    success,
    warning,
)
from teralibs.tsf.core.exe.builder import Exe
from teralibs.tsf.pex.poly import EncodingError
from teralibs.tsf.terax.compat import check_compat
from teralibs.tsf.terax.context import TeraxContext
from teralibs.tsf.terax.formatter import FORMATTERS
from teralibs.tsf.terax.helpers import (
    build_options,
    build_parser,
    detect_format,
    emit_output,
    encode_auto,
    encode_explicit,
    list_all,
    list_encoders,
    list_formats,
    list_payloads,
    missing_required,
    nop_sled,
    parse_overrides,
    resolve_payload,
    show_options,
)
from teralibs.tsf.utils.exception import TeraxGenerationError
from teralibs.tsf.utils.path import ModuleIndex


class Terax:
    """Payload generation pipeline for the terax CLI tool."""

    def __init__(self, args, modules, parser):
        """Initialise with parsed CLI args, a module index, and the argument parser."""
        self._args = args
        self._modules = modules
        self._parser = parser

        # Display start banner
        print_line(f"\n[*] starting @ {datetime.now():%H:%M:%S /%Y-%m-%d/}\n")

        # Handle listing operation
        self._handle_listing()

        # Get value for payload name, payload object, and formatter entry
        self._payload_name, self._payload_obj, self._formatter_entry = self._resolve_and_validate_payload()
        self._bad_bytes, self._ctx = self._build_generation_context()

    def run(self):
        """Execute the full payload generation pipeline."""
        try:
            payload = self._generate_raw_payload()
            payload = self._run_encoding_pipeline(payload)

            self._finalize_payload(payload)

        except (TeraxGenerationError, EncodingError) as exc:
            error(f"{exc}")

    def _handle_listing(self):
        """Dispatch early-exit listing modes; calls sys.exit(0) on match."""
        if not self._args.list_type:
            return

        dispatch = {
            "payloads": lambda: list_payloads(self._modules),
            "encoders": lambda: list_encoders(self._modules),
            "formats": list_formats,
            "all": lambda: list_all(self._modules),
        }
        dispatch[self._args.list_type]()
        sys.exit(0)

    def _resolve_and_validate_payload(self):
        """Resolve the payload class, handle --list-options, and validate the format."""
        if not self._args.payload:
            self._parser.print_help()
            sys.exit(1)

        payload_name, cls = resolve_payload(self._modules, self._args.payload)
        if cls is None or payload_name is None:
            sys.exit(1)

        payload_obj = cls()
        if self._args.list_options:
            show_options(payload_obj)
            sys.exit(0)

        arch_list = list(getattr(payload_obj, "ARCH", []) or [])
        plat_list = list(getattr(payload_obj, "PLATFORM", []) or [])

        # Auto-detect format when the user omitted -f / --format.
        if self._args.format == "raw" and not any(a in sys.argv for a in ("-f", "--format")):
            detected = detect_format(self._args.out, arch_list, plat_list)
            if detected != "raw":
                info(f"the selected format for this payload is '{detected}' this has been selected by auto-detection")
            self._args.format = detected

        fmt = self._args.format.lower()
        if fmt not in [f.name for f in FORMATTERS]:
            error(f"unknown format: {fmt!r}  (run 'terax -l formats' to list all supported formats)")
            sys.exit(1)

        compat = check_compat(fmt, arch_list, plat_list)
        for msg in compat.warnings:
            warning(msg)

        for msg in compat.errors:
            error(msg)

        if not compat.ok:
            sys.exit(1)

        formatter = next(f for f in FORMATTERS if f.name == fmt)
        return payload_name, payload_obj, (formatter.function, formatter.output_type, formatter.description)

    def _build_generation_context(self):
        """Merge options, enforce required fields, parse bad chars, and print the header."""
        overrides = parse_overrides(self._args.var_overrides)
        if self._args.iterations != 1 and "ITERATIONS" not in overrides:
            overrides["ITERATIONS"] = str(self._args.iterations)

        options = build_options(self._payload_obj, overrides)
        missing = missing_required(self._payload_obj, options)
        if missing:
            names_str = ", ".join(missing)
            example_str = " ".join(f"{k}=<value>" for k in missing)
            error(
                f"missing required option(s): {names_str}\n"
                f"  Provide them as VAR=value arguments, e.g.:\n"
                f"  terax -p {self._args.payload} {example_str}"
            )
            sys.exit(1)

        bc_str = self._args.bad_chars or str(getattr(self._payload_obj, "BADCHARS", "") or "")
        try:
            _bad_bytes = BadCharFilter.parse(bc_str) if bc_str else frozenset()

        except ValueError as exc:
            error(f"Cannot parse bad-char string: {exc}")
            sys.exit(1)

        self._print_generation_header(bc_str)
        _ctx = TeraxContext(options, verbose=self._args.verbose)

        return _bad_bytes, _ctx

    def _print_generation_header(self, bc_str):
        """Print the pre-generation summary block."""
        arch_list = list(getattr(self._payload_obj, "ARCH", []))
        plat_list = list(getattr(self._payload_obj, "PLATFORM", []))
        arch_noun = "architectures" if len(arch_list) > 1 else "architecture"

        info(f"using '{self._payload_name.replace('.', '/')}' to generate payload")
        info(f"the selected payload targets -> '{', '.join(plat_list) or 'any platform'}'")
        info(f"the selected payload supports -> '{', '.join(arch_list) or 'any'}' {arch_noun}")
        info(f"the selected or preferred output format for this payload -> {self._args.format.lower()}")

        if bc_str:
            info(f"bad character(s) specified -> '{bc_str}' this char will be excluded to prevent payload from being corrupted, truncated, or broken")

        if self._args.nop:
            noun = "bytes" if self._args.nop > 1 else "byte"
            info(f"nop sled size: {self._args.nop} {noun}")

        if self._args.space:
            noun = "bytes" if self._args.space > 1 else "byte"
            info(f"payload max size: {self._args.space} {noun}")

    def _generate_raw_payload(self):
        """Call payload_obj.generate(ctx) and return the raw payload."""
        try:
            raw_result = self._payload_obj.generate(self._ctx)

        except TeraxGenerationError as exc:
            error(f"payload generation failed: {exc}")
            if self._args.verbose:
                traceback.print_exc()
            sys.exit(1)

        if not isinstance(raw_result, (bytes, bytearray)) and isinstance(raw_result, str):
            return str(raw_result)

        if not isinstance(raw_result, (bytes, bytearray)):
            error(f"payload.generate() returned {type(raw_result).__name__!r} in fallback check - expected bytes.")
            sys.exit(1)

        return bytes(raw_result)

    def _run_encoding_pipeline(self, payload):
        """Run the encoder (explicit, auto, or skip) and perform a bad-char scan."""
        arch_list = list(getattr(self._payload_obj, "ARCH", []) or [])

        skip_encoding = self._args.encoder and self._args.encoder.lower() == "none"
        if not skip_encoding:
            if self._args.encoder:
                encoded = encode_explicit(payload, self._args.encoder, arch_list, self._bad_bytes, self._args.iterations)
                if encoded is None:
                    sys.exit(1)
                payload = encoded

            elif self._bad_bytes:
                payload = encode_auto(payload, arch_list, self._bad_bytes, self._args.verbose)

        if self._bad_bytes:
            scan = BadCharFilter.scan(payload, self._bad_bytes)
            if scan.clean:
                success("no bad characters found in the payload")

            else:
                warning(f"bad bytes still present after encoding: {scan.summary()}")
                print_line(BadCharFilter.format_hits(scan))
                print_line("byte map (xx = bad):\n" + BadCharFilter.byte_map(self._bad_bytes))

        return payload

    def _finalize_payload(self, payload):
        """Prepend NOP sled, enforce size limit, format, and emit the payload."""
        arch_list = list(getattr(self._payload_obj, "ARCH", []) or [])

        if self._args.nop > 0:
            sled = nop_sled(self._args.nop, arch_list)
            payload = sled + payload
            info(f"nop sled: {len(sled)} bytes prepended")

        shellcode_size = len(payload)
        if self._args.space > 0 and shellcode_size > self._args.space:
            error(f"payload size {shellcode_size} bytes exceeds size limit. aborting...")
            sys.exit(1)

        formatter_fn, fmt_kind, _ = self._formatter_entry
        fmt_name = self._args.format.lower()
        if fmt_name == "exe":
            exe = Exe(self._payload_obj.ARCH)
            formatted = exe.build(payload)

        else:
            arch_str = (arch_list[0] if arch_list else "x64") if fmt_name == "elf" else ""
            formatted = formatter_fn(payload, arch_str)

        output_size = len(formatted) if isinstance(formatted, bytes) else len(str(formatted))

        info(f"payload size: {shellcode_size:,} bytes")
        info(f"file size: {output_size:,} bytes in ({fmt_name}) format")

        emit_output(formatted, out_path=self._args.out, fmt_kind=fmt_kind, fmt_name=fmt_name)

    def __repr__(self):
        payload = getattr(self, "_payload_name", None) or getattr(self._args, "payload", None) or "unset"
        payload = payload.replace(".", "/")

        encoder = getattr(self._args, "encoder", None)
        bad_chars = getattr(self._args, "bad_chars", "")
        out = getattr(self._args, "out", None)

        parts = [f"payload={payload!r}", f"format={getattr(self._args, 'format', 'raw')!r}"]
        if encoder:
            parts.append(f"encoder={encoder!r}")
        if bad_chars:
            parts.append(f"bad_chars={bad_chars!r}")
        if out:
            parts.append(f"out={out!r}")

        return f"Terax({', '.join(parts)})"


def main():
    """Entry point: parse args, construct Terax, run the pipeline."""
    parser = build_parser()
    args = parser.parse_args()

    set_timestamp(True)
    try:
        if args.verbose:
            set_verbose(True)

        modules = ModuleIndex()
        Terax(args, modules, parser).run()

    finally:
        print(f"\n[*] ending @ {datetime.now():%H:%M:%S /%Y-%m-%d/}\n")
