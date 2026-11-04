import struct
import sys


# Builder debug state
DEBUG = False


def _log(msg: str) -> None:
    """
    Helper to output build state details clearly to standard error.
    """
    if DEBUG is True:
        sys.stderr.write(f"[~] {msg}\n")


def build_elf(code: bytes, arch: str) -> bytes:
    """
    Programmatically constructs a minimal Linux ELF executable wrapper around
    the provided shellcode, mirroring default Metasploit/msfvenom behavior.
    """
    # Architecture in module are stored in list because some module
    # supports multiple architecture. We select the first one as the default.
    if isinstance(arch, list):
        arch = arch[0]

    _log(f"Initiating programmatic ELF generation for architecture target: {arch}")
    _log(f"Payload size: {len(code)} bytes.")

    arch_clean = arch.lower().strip()

    # 32-Bit Linux Execution Path (x86 / i386 / i686)
    if arch_clean in ("x86", "i386", "i486", "i586", "i686"):
        _log("Configuring layout definitions for: ELFCLASS32 (32-bit)")

        load_vaddr = 0x08048000
        hdr_sz = 52
        phdr_sz = 32
        headers_sz = hdr_sz + phdr_sz  # 84 bytes

        total_size = headers_sz + len(code)
        entry_vaddr = load_vaddr + headers_sz

        # e_ident configuration
        e_ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8

        # Build main ELF32 header mapping layout
        elf_header = (
            e_ident
            + struct.pack("<H", 2)  # e_type: ET_EXEC
            + struct.pack("<H", 3)  # e_machine: EM_386
            + struct.pack("<I", 1)  # e_version: EV_CURRENT
            + struct.pack("<I", entry_vaddr)  # e_entry
            + struct.pack("<I", hdr_sz)  # e_phoff
            + struct.pack("<I", 0)  # e_shoff
            + struct.pack("<I", 0)  # e_flags
            + struct.pack("<H", hdr_sz)  # e_ehsize
            + struct.pack("<H", phdr_sz)  # e_phentsize
            + struct.pack("<H", 1)  # e_phnum
            + struct.pack("<H", 0)  # e_shentsize
            + struct.pack("<H", 0)  # e_shnum
            + struct.pack("<H", 0)  # e_shstrndx
        )

        # Build execution Program Header Segment mapping layout (PT_LOAD with RWX permissions)
        # Field ordering dictates flags trailing after memory size constraints on ELF32 targets
        phdr = (
            struct.pack("<I", 1)  # p_type: PT_LOAD
            + struct.pack("<I", 0)  # p_offset
            + struct.pack("<I", load_vaddr)  # p_vaddr
            + struct.pack("<I", load_vaddr)  # p_paddr
            + struct.pack("<I", total_size)  # p_filesz
            + struct.pack("<I", total_size)  # p_memsz
            + struct.pack("<I", 0x1 | 0x2 | 0x4)  # p_flags: PF_R | PF_W | PF_X
            + struct.pack("<I", 0x1000)  # p_align: 4KiB Alignment
        )

    # 64-Bit Linux Execution Path (x64 / AArch64 / ARM64)
    elif "64" in arch_clean or "arm64" in arch_clean or "aarch64" in arch_clean:
        _log("Configuring layout definitions for: ELFCLASS64 (64-bit)")

        # Determine specific operational target hardware architecture context
        if "arm" in arch_clean or "aarch" in arch_clean:
            em_machine = 183  # EM_AARCH64
            # Linux AArch64 traditionally uses 0x400000 or a higher default virtual space base
            load_vaddr = 0x400000
            # 4 KiB or 64 KiB alignment values are standard on modern ARM kernels
            p_align = 0x10000
        else:
            em_machine = 62  # EM_X86_64
            load_vaddr = 0x400000
            p_align = 0x200000  # 2MiB Alignment standard for x86_64 hugepages

        _log(f"Determined target EM_MACHINE structural index: {em_machine}")

        hdr_sz = 64
        phdr_sz = 56
        headers_sz = hdr_sz + phdr_sz  # 120 bytes

        total_size = headers_sz + len(code)
        entry_vaddr = load_vaddr + headers_sz

        # e_ident configuration
        e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8

        # Build main ELF64 header mapping layout
        elf_header = (
            e_ident
            + struct.pack("<H", 2)  # e_type: ET_EXEC
            + struct.pack("<H", em_machine)  # e_machine
            + struct.pack("<I", 1)  # e_version: EV_CURRENT
            + struct.pack("<Q", entry_vaddr)  # e_entry
            + struct.pack("<Q", hdr_sz)  # e_phoff
            + struct.pack("<Q", 0)  # e_shoff
            + struct.pack("<I", 0)  # e_flags
            + struct.pack("<H", hdr_sz)  # e_ehsize
            + struct.pack("<H", phdr_sz)  # e_phentsize
            + struct.pack("<H", 1)  # e_phnum
            + struct.pack("<H", 0)  # e_shentsize
            + struct.pack("<H", 0)  # e_shnum
            + struct.pack("<H", 0)  # e_shstrndx
        )

        # Build execution Program Header Segment mapping layout (PT_LOAD with RWX permissions)
        # Note: field ordering places flags immediately after type on ELF64 architectures
        phdr = (
            struct.pack("<I", 1)  # p_type: PT_LOAD
            + struct.pack("<I", 0x1 | 0x2 | 0x4)  # p_flags: PF_R | PF_W | PF_X
            + struct.pack("<Q", 0)  # p_offset
            + struct.pack("<Q", load_vaddr)  # p_vaddr
            + struct.pack("<Q", load_vaddr)  # p_paddr
            + struct.pack("<Q", total_size)  # p_filesz
            + struct.pack("<Q", total_size)  # p_memsz
            + struct.pack("<Q", p_align)  # Dynamic p_align factor based on platform matching rules
        )

    else:
        raise ValueError(f"Unsupported architecture request received: target profile '{arch}' unknown.")

    _log("Successfully finalized programmatic injection array compilation.")
    return bytes(elf_header + phdr + code)
