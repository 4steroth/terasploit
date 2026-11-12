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
from teralibs.tsf.pex.poly import EncodingError
from teralibs.tsf.terax.cli import TeraxCLI
from teralibs.tsf.terax.compat import CompatChecker
from teralibs.tsf.terax.context import TeraxContext
from teralibs.tsf.terax.display import TeraxDisplay
from teralibs.tsf.terax.encoder import TeraxEncoder
from teralibs.tsf.terax.formatter import FORMATTERS
from teralibs.tsf.terax.options import OptionBuilder
from teralibs.tsf.terax.output import TeraxOutput
from teralibs.tsf.terax.payload import PayloadResolver
from teralibs.tsf.utils.exception import TeraxGenerationError
from teralibs.tsf.utils.path import ModuleIndex


class Terax:
    """Coordinate payload resolution, generation, encoding, formatting, and output."""

    def __init__(self, args, modules, parser):
        """Initialise the generation pipeline and resolve its payload configuration."""
        self._args = args
        self._modules = modules
        self._parser = parser
        self._display = TeraxDisplay(modules)
        self._resolver = PayloadResolver(modules)

        print_line(f"\n[*] starting @ {datetime.now():%H:%M:%S /%Y-%m-%d/}\n")
        self._handle_listing()

        self._payload_name, self._payload_obj, self._formatter = self._resolve_payload()
        self._bad_chars, self._context = self._build_context()

    def run(self):
        """Execute the complete payload generation pipeline."""
        try:
            payload = self._generate_payload()
            payload = self._encode_payload(payload)
            self._emit_payload(payload)
        except (TeraxGenerationError, EncodingError) as exc:
            error(str(exc))

    def _handle_listing(self):
        """Handle listing modes before attempting to resolve a payload."""
        if not self._args.list_type:
            return

        dispatch = {
            "payloads": self._display.list_payloads,
            "encoders": self._display.list_encoders,
            "formats": self._display.list_formats,
            "all": self._display.list_all,
        }
        dispatch[self._args.list_type]()
        sys.exit(0)

    def _resolve_payload(self):
        """Resolve the payload module, validate its output format, and return its formatter."""
        if not self._args.payload:
            self._parser.print_help()
            sys.exit(1)

        payload_name, payload_class = self._resolver.resolve(self._args.payload)
        if payload_name is None or payload_class is None:
            sys.exit(1)

        payload_obj = payload_class()
        if self._args.list_options:
            self._display.show_options(payload_obj)
            sys.exit(0)

        arch = list(getattr(payload_obj, "ARCH", []) or [])
        platforms = list(getattr(payload_obj, "PLATFORM", []) or [])

        if self._format_was_omitted():
            detected = TeraxOutput.detect_format(self._args.out, arch, platforms)
            if detected != "raw":
                info(f"the selected format for this payload is '{detected}' this has been selected by auto-detection")
            self._args.format = detected

        requested_format = self._args.format.lower()
        formatter = self._find_formatter(requested_format)
        if formatter is None:
            error(f"unknown format: {requested_format!r} (run 'terax -l formats' to list all supported formats)")
            sys.exit(1)

        # The beta detector may select elf-aarch64, while the ELF formatter is
        # intentionally shared by all supported ELF architectures.
        compat_format = requested_format
        if requested_format == "elf-aarch64":
            compat_format = "elf-aarch64"
        elif requested_format == "elf-x64":
            compat_format = "elf-x64"

        compatibility = CompatChecker.check(compat_format, arch, platforms)
        for message in compatibility.warnings:
            warning(message)
        for message in compatibility.errors:
            error(message)
        if not compatibility.ok:
            sys.exit(1)

        return payload_name, payload_obj, formatter

    @staticmethod
    def _find_formatter(name):
        """Find a formatter by its canonical name, alias, or supported ELF variant."""
        canonical = "elf" if name in ("elf-aarch64", "elf-x64") else name
        for formatter in FORMATTERS:
            if formatter.name == canonical or name in formatter.aliases:
                return formatter
        return None

    def _format_was_omitted(self):
        """Return whether the operator omitted both format flags."""
        return not any(token in ("-f", "--format") or token.startswith("--format=") for token in sys.argv[1:])

    def _build_context(self):
        """Build resolved options, validate requirements, parse bad characters, and create context."""
        overrides = TeraxCLI.parse_overrides(self._args.var_overrides)
        if self._args.iterations != 1 and "ITERATIONS" not in overrides:
            overrides["ITERATIONS"] = str(self._args.iterations)

        options = OptionBuilder.build(self._payload_obj, overrides)
        missing = OptionBuilder.missing_required(self._payload_obj, options)
        if missing:
            names = ", ".join(missing)
            examples = " ".join(f"{name}=<value>" for name in missing)
            error(f"missing required option(s): {names}\n  provide them as VAR=value arguments, e.g.:\n  terax -p {self._args.payload} {examples}")
            sys.exit(1)

        bad_char_string = self._args.bad_chars or str(getattr(self._payload_obj, "BADCHARS", "") or "")
        try:
            bad_chars = BadCharFilter.parse(bad_char_string) if bad_char_string else frozenset()

        except ValueError as exc:
            error(f"cannot parse bad-char string: {exc}")
            sys.exit(1)

        self._print_generation_header(bad_char_string)
        context = TeraxContext(options, verbose=self._args.verbose)
        return bad_chars, context

    def _print_generation_header(self, bad_char_string):
        """Print the selected payload metadata and generation settings."""
        arch = list(getattr(self._payload_obj, "ARCH", []) or [])
        platforms = list(getattr(self._payload_obj, "PLATFORM", []) or [])
        arch_label = "architectures" if len(arch) > 1 else "architecture"

        info(f"using '{self._payload_name.replace('.', '/')}' to generate payload")
        info(f"the selected payload targets -> '{', '.join(platforms) or 'any platform'}'")
        info(f"the selected payload supports -> '{', '.join(arch) or 'any'}' {arch_label}")
        info(f"the selected or preferred output format for this payload -> {self._args.format.lower()}")

        if bad_char_string:
            info(
                f"bad character(s) specified -> '{bad_char_string}' "
                "this char will be excluded to prevent payload from being corrupted, truncated, or broken"
            )

        if self._args.nop:
            noun = "bytes" if self._args.nop != 1 else "byte"
            info(f"nop sled size: {self._args.nop} {noun}")

        if self._args.space:
            noun = "bytes" if self._args.space != 1 else "byte"
            info(f"payload max size: {self._args.space} {noun}")

    def _generate_payload(self):
        """Generate the raw payload through the resolved payload module."""
        try:
            result = self._payload_obj.generate(self._context)

        except TeraxGenerationError as exc:
            error(f"payload generation failed: {exc}")
            if self._args.verbose:
                traceback.print_exc()
            sys.exit(1)

        if isinstance(result, str):
            return result
        if not isinstance(result, (bytes, bytearray)):
            error(f"payload.generate() returned {type(result).__name__!r} - expected bytes or str")
            sys.exit(1)
        return bytes(result)

    def _encode_payload(self, payload):
        """Apply explicit or automatic encoding and report any remaining bad characters."""
        arch = list(getattr(self._payload_obj, "ARCH", []) or [])
        encoder = (self._args.encoder or "").lower()

        if encoder != "none":
            if self._args.encoder:
                payload = TeraxEncoder.encode_explicit(
                    payload,
                    self._args.encoder,
                    arch,
                    self._bad_chars,
                    self._args.iterations,
                )
                if payload is None:
                    sys.exit(1)
            elif self._bad_chars:
                payload = TeraxEncoder.encode_auto(payload, arch, self._bad_chars, self._args.verbose)

        if self._bad_chars:
            scan = BadCharFilter.scan(payload, self._bad_chars)
            if scan.clean:
                success("no bad characters found in the payload")
            else:
                warning(f"bad bytes still present after encoding: {scan.summary()}")
                print_line(BadCharFilter.format_hits(scan))
                print_line("byte map (xx = bad):\n" + BadCharFilter.byte_map(self._bad_chars))

        return payload

    def _emit_payload(self, payload):
        """Apply the NOP sled and size limit, format the payload, and write the result."""
        arch = list(getattr(self._payload_obj, "ARCH", []) or [])
        if self._args.nop > 0:
            if isinstance(payload, str):
                error("cannot prepend a NOP sled to a text payload")
                sys.exit(1)
            sled = TeraxOutput.nop_sled(self._args.nop, arch)
            payload = sled + payload
            info(f"nop sled: {len(sled)} bytes prepended")

        payload_size = len(payload)
        if self._args.space > 0 and payload_size > self._args.space:
            error(f"payload size {payload_size} bytes exceeds size limit. aborting...")
            sys.exit(1)

        format_name = self._args.format.lower()
        arch_name = arch[0] if arch else "x86"
        formatted = self._formatter.function(payload, arch_name)
        output_size = len(formatted) if isinstance(formatted, (bytes, bytearray)) else len(str(formatted))

        info(f"payload size: {payload_size:,} bytes")
        info(f"file size: {output_size:,} bytes in ({format_name}) format")
        TeraxOutput.emit(
            formatted,
            fmt_kind=self._formatter.output_type,
            out_path=self._args.out,
            fmt_name=format_name,
        )

    def __repr__(self):
        """Return a concise representation of the active generation configuration."""
        payload = (getattr(self, "_payload_name", None) or getattr(self._args, "payload", None) or "unset").replace(".", "/")
        parts = [
            f"payload={payload!r}",
            f"format={getattr(self._args, 'format', 'raw')!r}",
        ]

        encoder = getattr(self._args, "encoder", None)
        bad_chars = getattr(self._args, "bad_chars", "")
        output = getattr(self._args, "out", None)
        if encoder:
            parts.append(f"encoder={encoder!r}")
        if bad_chars:
            parts.append(f"bad_chars={bad_chars!r}")
        if output:
            parts.append(f"out={output!r}")
        return f"Terax({', '.join(parts)})"


def main():
    """Parse CLI arguments and execute the terax payload generation pipeline."""
    parser = TeraxCLI.build_parser()
    args = parser.parse_args()

    set_timestamp(True)
    try:
        if args.verbose:
            set_verbose(True)

        modules = ModuleIndex()
        Terax(args, modules, parser).run()

    finally:
        print(f"\n[*] ending @ {datetime.now():%H:%M:%S /%Y-%m-%d/}\n")
