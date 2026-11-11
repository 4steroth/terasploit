import struct

from teralibs.tsf.core.elf.constants import (
    ALIGN_ARM64,
    ALIGN_X64,
    ALIGN_X86,
    ELF32_HEADER_SIZE,
    ELF32_PHDR_SIZE,
    ELF64_HEADER_SIZE,
    ELF64_PHDR_SIZE,
    ELFCLASS32,
    ELFCLASS64,
    EM_386,
    EM_AARCH64,
    EM_X86_64,
    ET_EXEC,
    EV_CURRENT,
    LOAD_VADDR_ARM64,
    LOAD_VADDR_X64,
    LOAD_VADDR_X86,
    PF_RWX,
    PT_LOAD,
)
from teralibs.tsf.core.elf.utils import build_e_ident, is_arm64


def build_elf32_header(entry_vaddr: int) -> bytes:
    """Builds the 52-byte ELF32 header for an x86 executable."""
    return (
        build_e_ident(ELFCLASS32)
        + struct.pack("<H", ET_EXEC)
        + struct.pack("<H", EM_386)
        + struct.pack("<I", EV_CURRENT)
        + struct.pack("<I", entry_vaddr)
        + struct.pack("<I", ELF32_HEADER_SIZE)  # e_phoff
        + struct.pack("<I", 0)  # e_shoff
        + struct.pack("<I", 0)  # e_flags
        + struct.pack("<H", ELF32_HEADER_SIZE)  # e_ehsize
        + struct.pack("<H", ELF32_PHDR_SIZE)  # e_phentsize
        + struct.pack("<H", 1)  # e_phnum
        + struct.pack("<H", 0)  # e_shentsize
        + struct.pack("<H", 0)  # e_shnum
        + struct.pack("<H", 0)  # e_shstrndx
    )


def build_elf64_header(entry_vaddr: int, em_machine: int) -> bytes:
    """Builds the 64-byte ELF64 header for an x86_64 or AArch64 executable."""
    return (
        build_e_ident(ELFCLASS64)
        + struct.pack("<H", ET_EXEC)
        + struct.pack("<H", em_machine)
        + struct.pack("<I", EV_CURRENT)
        + struct.pack("<Q", entry_vaddr)
        + struct.pack("<Q", ELF64_HEADER_SIZE)  # e_phoff
        + struct.pack("<Q", 0)  # e_shoff
        + struct.pack("<I", 0)  # e_flags
        + struct.pack("<H", ELF64_HEADER_SIZE)  # e_ehsize
        + struct.pack("<H", ELF64_PHDR_SIZE)  # e_phentsize
        + struct.pack("<H", 1)  # e_phnum
        + struct.pack("<H", 0)  # e_shentsize
        + struct.pack("<H", 0)  # e_shnum
        + struct.pack("<H", 0)  # e_shstrndx
    )


def build_elf32_phdr(total_size: int) -> bytes:
    """Builds the 32-byte ELF32 PT_LOAD program header segment with RWX permissions."""
    # Field ordering: flags trail after memory size constraints on ELF32 targets
    return (
        struct.pack("<I", PT_LOAD)
        + struct.pack("<I", 0)  # p_offset
        + struct.pack("<I", LOAD_VADDR_X86)  # p_vaddr
        + struct.pack("<I", LOAD_VADDR_X86)  # p_paddr
        + struct.pack("<I", total_size)  # p_filesz
        + struct.pack("<I", total_size)  # p_memsz
        + struct.pack("<I", PF_RWX)
        + struct.pack("<I", ALIGN_X86)
    )


def build_elf64_phdr(total_size: int, arch: str) -> bytes:
    """Builds the 56-byte ELF64 PT_LOAD program header segment with RWX permissions."""
    # Field ordering: flags placed immediately after type on ELF64 architectures
    if is_arm64(arch):
        load_vaddr = LOAD_VADDR_ARM64
        p_align = ALIGN_ARM64

    else:
        load_vaddr = LOAD_VADDR_X64
        p_align = ALIGN_X64

    return (
        struct.pack("<I", PT_LOAD)
        + struct.pack("<I", PF_RWX)
        + struct.pack("<Q", 0)  # p_offset
        + struct.pack("<Q", load_vaddr)  # p_vaddr
        + struct.pack("<Q", load_vaddr)  # p_paddr
        + struct.pack("<Q", total_size)  # p_filesz
        + struct.pack("<Q", total_size)  # p_memsz
        + struct.pack("<Q", p_align)
    )


def resolve_em_machine(arch: str) -> int:
    """Resolves the ELF machine type constant for the given 64-bit architecture string."""
    return EM_AARCH64 if is_arm64(arch) else EM_X86_64
