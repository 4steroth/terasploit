from teralibs.tsf.core.elf.constants import (
    ELF32_HEADER_SIZE,
    ELF32_PHDR_SIZE,
    ELF64_HEADER_SIZE,
    ELF64_PHDR_SIZE,
    LOAD_VADDR_ARM64,
    LOAD_VADDR_X64,
    LOAD_VADDR_X86,
)
from teralibs.tsf.core.elf.header import (
    build_elf32_header,
    build_elf32_phdr,
    build_elf64_header,
    build_elf64_phdr,
    resolve_em_machine,
)
from teralibs.tsf.core.elf.utils import is_64bit, is_x86, validate_arch


class Elf:
    """Builds minimal Linux ELF executables for shellcode injection."""

    def __init__(self, arch: str = "x64") -> None:
        self._arch = validate_arch(arch)

    def build(self, code: bytes) -> bytes:
        """Wraps shellcode in a minimal ELF executable for the configured architecture."""
        arch = self._arch

        if is_x86(arch):
            return self._build_32(code)

        if is_64bit(arch):
            return self._build_64(code)

        raise ValueError(f"Unsupported architecture: '{arch}'.")

    def _build_32(self, code: bytes) -> bytes:
        """Constructs a minimal ELF32 executable around the given shellcode."""
        headers_size = ELF32_HEADER_SIZE + ELF32_PHDR_SIZE
        total_size = headers_size + len(code)
        entry_vaddr = LOAD_VADDR_X86 + headers_size

        elf_header = build_elf32_header(entry_vaddr)
        phdr = build_elf32_phdr(total_size)

        return bytes(elf_header + phdr + code)

    def _build_64(self, code: bytes) -> bytes:
        """Constructs a minimal ELF64 executable around the given shellcode."""
        arch = self._arch
        headers_size = ELF64_HEADER_SIZE + ELF64_PHDR_SIZE
        total_size = headers_size + len(code)

        load_vaddr = LOAD_VADDR_ARM64 if "arm" in arch or "aarch" in arch else LOAD_VADDR_X64
        entry_vaddr = load_vaddr + headers_size
        em_machine = resolve_em_machine(arch)

        elf_header = build_elf64_header(entry_vaddr, em_machine)
        phdr = build_elf64_phdr(total_size, arch)

        return bytes(elf_header + phdr + code)

    def __repr__(self) -> str:
        """Returns a developer-facing representation of the ELFBuilder instance."""
        return f"ELFBuilder(arch={self._arch!r})"
