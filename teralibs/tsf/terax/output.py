import os
import stat
import sys

from teralibs.terasploit.framework.services.printf import error, print_line, success


# Architecture-specific NOP encodings.
_THUMB2_NOP = b"\x00\xbf"  # Thumb2:   MOV r0, r0  (2 bytes)
_AARCH64_NOP = b"\x1f\x20\x03\xd5"  # AArch64:  NOP         (4 bytes, LE)
_X86_NOP = b"\x90"  # x86/x64:  NOP         (1 byte)

# Maps output-file extensions to canonical format names; first match wins.
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


class TeraxOutput:
    """Format detection, NOP sled generation, and payload file emission."""

    @staticmethod
    def detect_format(out_path, arch_list, platform_list):
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

    @staticmethod
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

    @staticmethod
    def emit(data, fmt_kind, out_path, fmt_name=""):
        """Write formatted payload output to a file or to stdout."""
        # Normalise types before any I/O so callers never need to care.
        if fmt_kind != "binary":
            if isinstance(data, (bytes, bytearray)):
                data = data.decode("utf-8", errors="replace")
        else:
            if isinstance(data, str):
                data = data.encode("utf-8")
            elif not isinstance(data, (bytes, bytearray)):
                error(f"emit: unexpected type {type(data).__name__!r} for binary formatter {fmt_name!r} — aborting.")
                sys.exit(1)

        if out_path:
            path = os.path.expanduser(out_path)
            mode = "wb" if fmt_kind == "binary" else "w"
            try:
                with open(path, mode) as fh:
                    fh.write(data)
                success(f"payload saved: {path}")

            except OSError as exc:
                error(f"cannot write to {out_path!r}: {exc}")
                sys.exit(1)

            if fmt_name.lower() in ("elf", "elf-aarch64", "exe"):
                try:
                    st_mode = os.stat(path).st_mode
                    os.chmod(path, st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    success("executable permission has been applied")
                except OSError as exc:
                    error(f"could not set executable bit on {path!r}: {exc}")

        elif fmt_kind == "binary":
            assert isinstance(data, bytes)
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

        else:
            print_line(data, end="")
