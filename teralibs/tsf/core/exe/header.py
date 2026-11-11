import struct

from teralibs.tsf.core.exe.constants import MACHINE_AMD64, MACHINE_I386


def parse(pe: bytearray) -> tuple[int, int]:
    """Parses and validates the DOS and PE signatures, returning pe_offset and machine type."""
    if pe[0:2] != b"MZ":
        raise ValueError("Invalid DOS header signature (missing 'MZ').")

    pe_offset = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature.")

    machine = struct.unpack_from("<H", pe, pe_offset + 4)[0]
    return pe_offset, machine


def arch_offsets(machine: int) -> tuple[int, int, int, str]:
    """Returns architecture-specific Optional Header field offsets for the given machine type."""
    if machine == MACHINE_AMD64:
        return 16, 24, 70, "Q"

    if machine == MACHINE_I386:
        return 16, 28, 68, "I"

    raise ValueError(f"Unsupported machine architecture: {hex(machine)}")


def validate_arch(arch: str | list) -> str:
    """Validates and normalizes the target architecture string to 'x86' or 'x64'."""
    if isinstance(arch, list):
        arch = arch[0]

    if isinstance(arch, str):
        arch = arch.lower().strip()

    if not arch:
        raise ValueError(f"Invalid architecture was specified: {arch!r}")

    if arch not in ("x86", "x64"):
        raise ValueError("Invalid architecture string. Choose 'x86' or 'x64'.")
    return arch
