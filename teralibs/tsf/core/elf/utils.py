from teralibs.tsf.core.elf.constants import ELFDATA2LSB, ELFMAG, ELFOSABI_NONE


def build_e_ident(elf_class: int) -> bytes:
    """Builds the 16-byte ELF e_ident field for the given ELF class (32 or 64 bit)."""
    return ELFMAG + bytes([elf_class]) + bytes([ELFDATA2LSB]) + bytes([ELFOSABI_NONE]) + b"\x00" + b"\x00" * 8


def validate_arch(arch: str | list) -> str:
    """Validates and normalizes the target architecture string."""
    if isinstance(arch, list):
        arch = str(arch[0])

    if isinstance(arch, str):
        arch = arch.lower().strip()

    if not arch:
        raise ValueError(f"Invalid architecture was specified: {arch!r}")

    return arch


def is_x86(arch: str) -> bool:
    """Returns True if the architecture is a 32-bit x86 variant."""
    return arch in ("x86", "i386", "i486", "i586", "i686")


def is_64bit(arch: str) -> bool:
    """Returns True if the architecture is a 64-bit variant."""
    return "64" in arch or "arm64" in arch or "aarch64" in arch


def is_arm64(arch: str) -> bool:
    """Returns True if the architecture is ARM64/AArch64."""
    return "arm" in arch or "aarch" in arch
