import sys
import traceback

from teralibs.terasploit.framework.payload.badchars import BadCharFilter
from teralibs.terasploit.framework.services.printf import error, set_verbose, warning
from teralibs.tsf.core.builder.pe import build_pe
from teralibs.tsf.terax.compat import check_compat
from teralibs.tsf.terax.context import TeraxContext
from teralibs.tsf.terax.formatter import FORMATTERS
from teralibs.tsf.terax.helpers import (
    build_options,
    build_parser,
    detect_format,
    diag,
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
from teralibs.tsf.terax.options import opt_name
from teralibs.tsf.utils.exception import TeraxGenerationError
from teralibs.tsf.utils.path import ModuleIndex


# Private pipeline helpers


def _handle_listing(args, modules):
    """Dispatch early-exit listing modes and call sys.exit(0) on match."""
    if not args.list_type:
        return
    listing_dispatch = {
        "payloads": lambda: list_payloads(modules),
        "encoders": lambda: list_encoders(modules),
        "formats": list_formats,
        "all": lambda: list_all(modules),
    }
    listing_dispatch[args.list_type]()
    sys.exit(0)


def _resolve_and_validate_payload(args, modules, parser):
    """Resolve payload name + class, handle --list-options, and validate format."""
    if not args.payload:
        parser.print_help()
        sys.exit(1)

    payload_name, cls = resolve_payload(modules, args.payload)
    if cls is None or payload_name is None:
        sys.exit(1)

    payload_obj = cls()

    if args.list_options:
        show_options(payload_obj)
        sys.exit(0)

    arch_list: list[str] = list(getattr(payload_obj, "ARCH", []) or [])
    plat_list: list[str] = list(getattr(payload_obj, "PLATFORM", []) or [])

    # Auto-detect format when the user omitted -f / --format.
    # argparse sets args.format to "raw" as its default, so we compare
    # against the parser's registered default to distinguish "user typed
    # -f raw" from "user left -f out entirely".
    if args.format == "raw" and not any(a in sys.argv for a in ("-f", "--format")):
        detected = detect_format(args.out, arch_list, plat_list)
        if detected != "raw":
            diag(f"[-] Format    : {detected}  (auto-detected)")
        args.format = detected

    fmt = args.format.lower()
    if fmt not in [f.name for f in FORMATTERS]:
        error(f"Unknown format: {fmt!r}  (run 'terax -l formats' to list all supported formats)")
        sys.exit(1)

    compat = check_compat(fmt, arch_list, plat_list)
    for msg in compat.warnings:
        warning(msg)
    for msg in compat.errors:
        error(msg)
    if not compat.ok:
        sys.exit(1)

    return (
        payload_name,
        payload_obj,
        next((f.function, f.output_type, f.description) for f in FORMATTERS if f.name == fmt),
    )


def _build_generation_context(args, payload_name, payload_obj):
    """
    Merge options, enforce required fields, parse bad chars, and print the
    generation header to stderr.
    """
    overrides = parse_overrides(args.var_overrides)
    if args.iterations != 1 and "ITERATIONS" not in overrides:
        overrides["ITERATIONS"] = str(args.iterations)

    options = build_options(payload_obj, overrides)

    missing = missing_required(payload_obj, options)
    if missing:
        names_str = ", ".join(missing)
        example_str = " ".join(f"{k}=<value>" for k in missing)
        error(f"Missing required option(s): {names_str}\n  Provide them as VAR=value arguments, e.g.:\n  terax -p {args.payload} {example_str}")
        sys.exit(1)

    bc_str = args.bad_chars or str(getattr(payload_obj, "BADCHARS", "") or "")
    try:
        bad_bytes: frozenset[int] = BadCharFilter.parse(bc_str) if bc_str else frozenset()
    except ValueError as exc:
        error(f"Cannot parse bad-char string: {exc}")
        sys.exit(1)

    _print_generation_header(args, payload_name, payload_obj, options, bc_str)

    ctx = TeraxContext(options, verbose=args.verbose)
    return bad_bytes, ctx


def _print_generation_header(args, payload_name, payload_obj, options, bc_str) -> None:
    """Print the pre-generation diagnostic block to stderr."""
    arch_list: list[str] = list(getattr(payload_obj, "ARCH", []) or [])
    plat_list: list[str] = list(getattr(payload_obj, "PLATFORM", []) or [])

    payload_opt_keys: set[str] = {opt_name(o).upper() for o in (getattr(payload_obj, "OPTIONS", None) or [])}
    user_opts = {k: v for k, v in options.items() if k in payload_opt_keys}

    # Header info about the payload being generated, including the resolved name,
    # platform/arch (if specified by the module), and any user-specified options.
    diag(f"[-] Payload   : {payload_name.replace('.', '/')}")
    diag(f"[-] Platform  : {', '.join(plat_list) or 'any'}")
    diag(f"[-] Arch      : {', '.join(arch_list) or 'any'}")

    # Bad chars are emitted last in the header since they are often the most critical
    # constraint and we want them to stand out visually.  If bad chars are present,
    # we also emit a byte map at the end of the post-encode scan to visually
    # reinforce which bytes are bad and which are not.
    if bc_str:
        diag(f"[-] BadChars  : {bc_str}")

    # If the user specified a NOP sled, report that as well since it's a common technique
    # for evading bad chars and it contributes to the final size of the payload.
    if args.nop:
        diag(f"[-] NOP sled  : {args.nop} bytes")

    # If the user specified a size constraint, report that too since it's a critical constraint
    # that often requires multiple iterations of tweaking and regenerating to get right.
    if args.space:
        diag(f"[-] Max space : {args.space} bytes")

    # Finally, report the output format (container) being generated.  This is important to confirm
    # since the format determines how the raw payload bytes will be transformed before output,
    # and the user may have expected a different format if they forgot to specify -f or
    # auto-detection chose a different format than they expected.
    diag(f"[-] Format    : {args.format.lower()}")

    # Display the user-specified options in a clear, aligned format.
    diag("\nOPTIONS:\n")
    for k, v in user_opts.items():
        diag(f"  * {k:<10}=> {v}")

    # Newline after options for readability, especially when many options are present.
    diag("\n")


def _generate_raw_payload(args, payload_obj, ctx) -> bytes | str:
    """Call payload_obj.generate(ctx) and return the raw bytes."""
    try:
        raw_result: object = payload_obj.generate(ctx)

    except TeraxGenerationError as exc:
        error(f"Payload generation failed: {exc}")

        if args.verbose:
            traceback.print_exc()
        sys.exit(1)

    if not isinstance(raw_result, (bytes, bytearray)) and isinstance(raw_result, str):
        # Return string raw result.
        return str(raw_result)

    # We still do this to make sure we are returning the correct object.
    if not isinstance(raw_result, (bytes, bytearray)):
        error(f"payload.generate() returned {type(raw_result).__name__!r} in fallback check - expected bytes.")
        sys.exit(1)

    payload: bytes = bytes(raw_result)
    return payload


def _run_encoding_pipeline(args, payload, payload_obj, bad_bytes: frozenset[int]) -> bytes:
    """
    Run the encoding pipeline (explicit encoder, auto, or skip) then perform
    a post-encode bad-char scan.
    """
    arch_list: list[str] = list(getattr(payload_obj, "ARCH", []) or [])
    skip_encoding = args.encoder and args.encoder.lower() == "none"

    if not skip_encoding:
        if args.encoder:
            encoded = encode_explicit(
                payload,
                args.encoder,
                arch_list,
                bad_bytes,
                args.iterations,
            )
            if encoded is None:
                sys.exit(1)
            payload = encoded
        elif bad_bytes:
            payload = encode_auto(payload, arch_list, bad_bytes, args.verbose)

    if bad_bytes:
        scan = BadCharFilter.scan(payload, bad_bytes)
        if scan.clean:
            diag("[+] No bad characters found.")
        else:
            warning(f"Bad bytes still present after encoding: {scan.summary()}")
            diag(BadCharFilter.format_hits(scan))
            diag("Byte map (xx = bad):\n" + BadCharFilter.byte_map(bad_bytes))

    return payload


def _finalize_payload(args, payload: bytes, payload_obj, formatter_entry) -> None:
    """Prepend NOP sled, enforce size constraint, format, and emit the payload."""
    arch_list: list[str] = list(getattr(payload_obj, "ARCH", []) or [])

    if args.nop > 0:
        sled = nop_sled(args.nop, arch_list)
        payload = sled + payload
        diag(f"[-] NOP sled: {len(sled)} bytes prepended")

    # Size-limit check before formatting
    shellcode_size = len(payload)
    if args.space > 0 and shellcode_size > args.space:
        error(f"Payload size {shellcode_size} bytes exceeds --space limit. Aborting.")
        sys.exit(1)

    formatter_fn, fmt_kind, _ = formatter_entry
    fmt_name = args.format.lower()

    if fmt_name == "exe":
        formatted = build_pe(payload, payload_obj.ARCH)
    else:
        # Standard text/hex/raw formatting
        arch_str = (arch_list[0] if arch_list else "x64") if fmt_name == "elf" else ""
        formatted = formatter_fn(payload, arch_str)

    # Calculate final output size for reporting
    output_size = len(formatted) if isinstance(formatted, bytes) else len(str(formatted))

    diag(f"{'Payload size':<13} => {shellcode_size} bytes")
    diag(f"{'File size':<13} => {output_size} bytes  ({fmt_name} container)\n")

    # emit_output handles the binary vs text mode automatically based on fmt_kind
    emit_output(formatted, out_path=args.out, fmt_kind=fmt_kind, fmt_name=fmt_name)


# Entry point


def main() -> None:
    """Entry point for the terax payload generator."""
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        set_verbose(True)

    modules = ModuleIndex()
    _handle_listing(args, modules)

    payload_name, payload_obj, formatter_entry = _resolve_and_validate_payload(
        args,
        modules,
        parser,
    )

    bad_bytes, ctx = _build_generation_context(args, payload_name, payload_obj)
    payload = _generate_raw_payload(args, payload_obj, ctx)
    payload = _run_encoding_pipeline(args, payload, payload_obj, bad_bytes)

    _finalize_payload(args, payload, payload_obj, formatter_entry)
