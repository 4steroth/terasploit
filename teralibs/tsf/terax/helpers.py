import argparse
import os
import shutil
import stat
import sys
import textwrap

from teralibs.terasploit.framework.encoder.factory import EncoderFactory
from teralibs.terasploit.framework.options.storage import (
    OPTION_REGISTRY,
    PAYLOAD_ADVANCED_OPTIONS,
    PAYLOAD_EVASION_OPTIONS,
)
from teralibs.terasploit.framework.services.printf import (
    error,
    print_line,
    warning,
)
from teralibs.terasploit.framework.services.tables import modules_table
from teralibs.tsf.terax.formatter import FORMATTERS
from teralibs.tsf.terax.options import (
    opt_default,
    opt_name,
    opt_required,
)


# Internal constants

_FORMAT_ALIASES = frozenset({"py", "rb", "pl", "sh", "ps1"})

# Thumb2  NOP  (2 bytes: MOV r0, r0)
_THUMB2_NOP = b"\x00\xbf"

# AArch64 NOP  (4 bytes, LE)
_AARCH64_NOP = b"\x1f\x20\x03\xd5"

# x86/x64 NOP  (1 byte)
_X86_NOP = b"\x90"

# Maps output-file extensions to canonical format names.
# Checked in order; first match wins.
_EXT_FORMAT_MAP = {
    ".bin": "raw",
    ".raw": "raw",
    ".elf": "elf",
    ".exe": "exe",
    ".hex": "hex",
    ".b64": "base64",
    ".py": "python",
    ".rb": "ruby",
    ".pl": "perl",
    ".sh": "bash",
    ".ps1": "powershell",
    ".cs": "csharp",
    ".java": "java",
    ".c": "c",
    ".asp": "asp",
}

_INDENT = "   "
_GAP = "  "
_HEADERS = ("Name", "Current Setting", "Required", "Description")


# Format auto-detection


def detect_format(
    out_path,
    arch_list,
    platform_list,
):
    """Infer the best output format when the user omits -f / --format."""
    if out_path:
        ext = os.path.splitext(out_path)[1].lower()
        if ext in _EXT_FORMAT_MAP:
            return _EXT_FORMAT_MAP[ext]

    arch_norm = [a.lower().strip() for a in arch_list if a]
    plat_norm = [p.lower().strip() for p in platform_list if p]

    is_windows = "windows" in plat_norm
    is_linux = "linux" in plat_norm
    is_arm = any(a in arch_norm for a in ("arm64", "aarch64", "arm"))
    is_x64 = "x64" in arch_norm
    is_x86 = "x86" in arch_norm

    if is_windows and (is_x64 or not arch_norm):
        return "exe"

    if is_linux and is_arm:
        return "elf-aarch64"

    if is_linux and (is_x64 or is_x86 or not arch_norm):
        return "elf"

    return "raw"


# Diagnostics


def diag(msg=""):
    """Write a diagnostic line to stderr via the framework's print_line()."""
    print_line(msg, file=sys.stderr)


# Rank helper


def rank_label(rank):
    """Return the human-readable label for an encoder rank object."""
    label_fn = getattr(rank, "label", None)
    return label_fn() if callable(label_fn) else str(rank)


# Listing helpers


def list_payloads(modules):
    """Print a formatted table of all available payload modules to stdout."""
    items = sorted(m for m in modules.list() if m.startswith("payload.singles") or m.startswith("payload.stagers"))

    print_line(f"\nPayloads ({len(items)})")
    modules_table(items)

    print_line()


def list_encoders(modules):
    """Print a formatted table of all registered encoder modules to stdout."""
    items = sorted(m for m in modules.list() if m.startswith("encoder."))

    print_line(f"\nEncoders ({len(items)})")
    modules_table(items)

    print_line()


def list_formats():
    """Print a formatted table of all supported output formats to stdout."""
    print_line("\nOutput Formats\n")
    groups = {}

    for name, kind, desc in ((f.name, f.output_type, f.description) for f in FORMATTERS):
        if name not in _FORMAT_ALIASES:
            groups.setdefault(kind, []).append((name, desc))

    for kind in ("binary", "text"):
        label = "Binary" if kind == "binary" else "Transform / Display"

        print_line(f"{label}")
        print_line(f"{'-' * len(label)}\n")

        for name, desc in sorted(groups.get(kind, [])):
            print_line(f"    {name:<16} {desc}")

        print_line("\n")


def list_all(modules):
    """Print payloads, encoders, and formats in sequence."""
    list_payloads(modules)
    list_encoders(modules)
    list_formats()


# Option helpers


def show_options(payload_obj):
    """Print the option table for payload_obj."""
    wanted = set(getattr(payload_obj, "OPTIONS", None) or [])
    rows = [
        (opt.name, str(opt.default or ""), str(opt.required == 1).lower(), opt.desc) for key, opt in OPTION_REGISTRY.items() if key.upper() in wanted
    ]
    if not rows:
        return

    widths = [max(len(_HEADERS[i]), *(len(row[i]) for row in rows)) for i in range(3)]
    # Description gets whatever terminal width remains, with a sane floor.
    used = len(_INDENT) + sum(widths) + len(_GAP) * 3
    desc_width = max(shutil.get_terminal_size().columns - used, 30)

    def fmt(name, setting, required, desc):
        cells = (name, setting, required)
        left = _GAP.join(f"{c:<{w}}" for c, w in zip(cells, widths, strict=True))
        return f"{_INDENT}{left}{_GAP}{desc}".rstrip()

    print_line("Basic options:\n")
    print_line(fmt(*_HEADERS))
    print_line(fmt(*("-" * len(h) for h in _HEADERS)))

    for name, setting, required, desc in rows:
        first, *rest = textwrap.wrap(desc, desc_width) or [""]
        print_line(fmt(name, setting, required, first))
        for line in rest:
            print_line(fmt("", "", "", line))

    print_line("\n")


def build_options(
    payload_obj,
    overrides,
):
    """Merge option defaults and CLI overrides into a single resolved dict."""
    options = {}

    for o in getattr(payload_obj, "OPTIONS", None) or []:
        k = opt_name(o)
        # If o is a plain string, look up the real default from OPTION_REGISTRY
        v = opt_default(o)
        if v == k:  # opt_default returned the key name - raw string case
            registry_opt = OPTION_REGISTRY.get(k.upper())
            v = registry_opt.default if registry_opt else None
        if k and v is not None:
            options[k.upper()] = v

    for o in PAYLOAD_ADVANCED_OPTIONS:
        key = o.name.upper()
        if key not in options and o.default is not None:
            options[key] = o.default

    # After seeding OPTIONS and PAYLOAD_ADVANCED_OPTIONS:

    for o in getattr(payload_obj, "ADVANCED_OPTIONS", None) or []:
        k = opt_name(o)
        if k.upper() not in options:
            registry_opt = OPTION_REGISTRY.get(k.upper())
            if registry_opt and registry_opt.default is not None:
                options[k.upper()] = registry_opt.default

    # Evasion option defaults (EnableStageEncoding, EXITFUNC, etc.) must also
    # be seeded here so the assembler can read them via ctx.get_option() even
    # when the operator has not explicitly set them.
    for o in PAYLOAD_EVASION_OPTIONS:
        key = o.name.upper()
        if key not in options and o.default is not None:
            options[key] = o.default

    options.update(overrides)
    return options


def missing_required(
    payload_obj,
    options,
):
    """Return the names of required options that have no value in options."""
    missing = []
    for o in getattr(payload_obj, "OPTIONS", None) or []:
        name = opt_name(o)
        if name and opt_required(o) and not options.get(name.upper()) and not opt_default(o):
            missing.append(name)
    return missing


# Payload resolution


def resolve_payload(
    modules,
    raw,
):
    """Resolve a raw user payload string to (dotted_name, TerasploitModule)."""
    name = raw.replace("/", ".").removeprefix("modules.")

    if modules.get_path(name) is None:
        matches = modules.search(name)
        if not matches:
            stem = raw.split("/")[-1].replace("-", "_")
            hits = [m for m in modules.list() if m.startswith("payload.") and stem in m]
            if hits:
                warning(f"Payload {raw!r} not found. Did you mean:")
                for m in hits[:5]:
                    print_line(f"    {m.replace('.', '/')}")
            else:
                error(f"Payload not found: {raw!r}  (run 'terax -l payloads' to list)")
            return None, None

        if len(matches) > 1:
            warning(f"Ambiguous - {len(matches)} modules match {raw!r}:")
            for m in matches[:10]:
                print_line(f"    {m.replace('.', '/')}")
            return None, None

        name = matches[0]

    mod = modules.load(name)
    if mod is None:
        error(f"Failed to load: {name!r}")
        return None, None

    cls = getattr(mod, "TerasploitModule", None)
    if cls is None:
        error(f"{name!r} does not define a TerasploitModule class.")
        return None, None

    return name, cls


# CLI parser


class _CompactHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """RawDescriptionHelpFormatter with a tighter help-column alignment."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_help_position", 50)
        kwargs.setdefault("width", 100)
        super().__init__(*args, **kwargs)


def build_parser():
    """Construct and return the terax CLI argument parser."""
    p = argparse.ArgumentParser(
        prog="terax",
        formatter_class=_CompactHelpFormatter,
        add_help=True,
    )
    p.add_argument(
        "-p",
        "--payload",
        default=None,
        help="Payload path  (e.g. payload/stagers/linux/x64/reverse_tcp)",
    )
    p.add_argument(
        "-e",
        "--encoder",
        default=None,
        help="Encoder to use  (e.g. encoder/x64/xor_dynamic  or 'none')",
    )
    p.add_argument(
        "-i",
        "--iterations",
        default=1,
        type=int,
        help="Encoding iterations  (default: 1)",
    )
    p.add_argument(
        "-b",
        "--bad-chars",
        default="",
        dest="bad_chars",
        help=r"Bad chars in \xNN notation  (e.g. '\x00\x0a\x0d')",
    )
    p.add_argument(
        "-n",
        "--nop-sled",
        default=0,
        type=int,
        dest="nop",
        help="Prepend N NOP bytes to the payload",
    )
    p.add_argument(
        "-s",
        "--space",
        default=0,
        type=int,
        help="Maximum payload size in bytes  (0 = unlimited)",
    )
    p.add_argument(
        "-f",
        "--format",
        default="raw",
        help="Output format  (default: raw, see -l formats)",
    )
    p.add_argument(
        "-o",
        "--out",
        default=None,
        help="Output file  (default: stdout)",
    )
    p.add_argument(
        "--list-options",
        action="store_true",
        help="Show payload options then exit  (requires -p)",
    )
    p.add_argument(
        "-l",
        "--list",
        default=None,
        dest="list_type",
        choices=["payloads", "encoders", "formats", "all"],
        help="List payloads | encoders | formats | all",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose pipeline output",
    )
    p.add_argument(
        "var_overrides",
        nargs="*",
        help="Payload / advanced option overrides  (e.g. LHOST=10.0.0.1)",
    )
    return p


def parse_overrides(tokens):
    """Parse VAR=value CLI tokens into an uppercase-keyed option dict."""
    out = {}
    for tok in tokens:
        if "=" not in tok:
            error(f"Unrecognised argument (expected VAR=value): {tok!r}")
            sys.exit(1)
        k, _, v = tok.partition("=")
        out[k.strip().upper()] = v.strip()
    return out


# Encoding pipeline


def encode_explicit(
    payload,
    encoder_name,
    arch,
    bad_bytes,
    iterations,
):
    """Run a named encoder for iterations passes over payload."""
    name_norm = encoder_name.replace("/", ".").removeprefix("modules.encoder.")
    diag(f"[-] Encoder   : {name_norm}  ({iterations} iteration(s))\n")

    current = payload
    for n in range(1, iterations + 1):
        result = EncoderFactory.encode_payload(
            raw_bad_bytes=(current, bad_bytes),
            encoder_name=name_norm,
            arch=arch,
        )

        if not result.success:
            error(f"Encoding failed at iteration {n}: {result.error}")
            return None

        current = result.encoded_bytes
        diag(f"[pass {n}] {len(current):<5} => bytes{f'key=0x{result.key_used:02x}' if isinstance(result.key_used, int) else ''}")
    diag()

    return current


def encode_auto(
    payload,
    arch,
    bad_bytes,
    verbose,
):
    """Auto-select and apply the highest-ranked compatible encoder."""
    candidates = EncoderFactory.suggest(bad_bytes, arch)
    if not candidates:
        warning("No compatible encoder found for the specified bad chars - delivering unencoded payload.  Specify -e manually.")
        return payload

    chosen = candidates[0]
    rank = rank_label(chosen.RANK)
    diag(f"[-] Auto-selecting encoder: {chosen.NAME}  (rank: {rank})")

    result = EncoderFactory.encode_payload(
        raw_bad_bytes=(payload, bad_bytes),
        encoder_name=chosen.NAME,
        arch=arch,
    )

    if not result.success:
        warning(f"Auto-encoding failed: {result.error} - delivering unencoded.")
        return payload

    if verbose:
        key_tag = f"  key=0x{result.key_used:02x}" if isinstance(result.key_used, int) else ""
        diag(f"    encoded: {len(result.encoded_bytes):,} bytes{key_tag}")

    return result.encoded_bytes


# NOP sled


def nop_sled(count, arch):
    """Return *count* NOP bytes suitable for the target architecture."""
    if not arch:
        return _X86_NOP * count

    a = arch[0].lower()

    if a in ("arm64", "aarch64"):
        # AArch64: instructions are always 4 bytes; truncate to alignment.
        return _AARCH64_NOP * (count // 4)

    if a == "arm":
        # Thumb2: 2-byte NOPs; append one padding byte for odd counts.
        return _THUMB2_NOP * (count // 2) + (b"\x00" if count % 2 else b"")

    return _X86_NOP * count


# Output


def emit_output(data, fmt_kind, out_path, fmt_name=""):
    """Write formatted payload output to a file or to stdout."""

    # Normalise types before any I/O so callers never need to care.
    if fmt_kind != "binary":
        if isinstance(data, (bytes, bytearray)):
            data = data.decode("utf-8", errors="replace")
    else:
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif not isinstance(data, (bytes, bytearray)):
            error(f"emit_output: unexpected type {type(data).__name__!r} for binary formatter {fmt_name!r} — aborting.")
            sys.exit(1)

    if out_path:
        path = os.path.expanduser(out_path)
        mode = "wb" if fmt_kind == "binary" else "w"
        try:
            with open(path, mode) as fh:
                fh.write(data)
            diag(f"[+] Saved to: {path}")
        except OSError as exc:
            error(f"Cannot write to {out_path!r}: {exc}")
            sys.exit(1)

        if fmt_name.lower() in ("elf", "elf-aarch64", "exe"):
            try:
                current = os.stat(path).st_mode
                os.chmod(path, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                diag("[+] Permissions: +x applied")
            except OSError as exc:
                error(f"Could not set executable bit on {path!r}: {exc}")

    elif fmt_kind == "binary":
        assert isinstance(data, bytes)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    else:
        print_line(data, end="")
