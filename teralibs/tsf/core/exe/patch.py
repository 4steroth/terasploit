import struct

from teralibs.tsf.core.exe.constants import (
    DLLCHAR_DYNAMIC_BASE,
    DLLCHAR_HIGH_ENTROPY_VA,
    SECTION_ALIGNMENT,
    STANDARD_SECTION_NAMES,
)
from teralibs.tsf.core.exe.utils import align


def strip_aslr(pe: bytearray, pe_offset: int, dll_chars_offset: int) -> None:
    """Clears DYNAMIC_BASE and HIGH_ENTROPY_VA from DllCharacteristics."""
    offset = pe_offset + 24 + dll_chars_offset
    flags = struct.unpack_from("<H", pe, offset)[0]
    flags &= ~(DLLCHAR_DYNAMIC_BASE | DLLCHAR_HIGH_ENTROPY_VA)
    struct.pack_into("<H", pe, offset, flags)


def update_size_of_image(pe: bytearray, pe_offset: int, payload_va: int, code_size: int) -> None:
    """Updates SizeOfImage in the Optional Header to cover the newly added section."""
    offset = pe_offset + 24 + 56
    struct.pack_into("<I", pe, offset, align(payload_va + code_size, SECTION_ALIGNMENT))


def update_entry_point(pe: bytearray, pe_offset: int, ep_offset: int, virtual_addr: int) -> None:
    """Sets the Optional Header AddressOfEntryPoint to the new section's virtual address."""
    struct.pack_into("<I", pe, pe_offset + 24 + ep_offset, virtual_addr)


def add_write_permission(data: bytes | bytearray, section_name: bytes | None = None) -> bytearray:
    """Patches a PE section to allow self-modifying code, clearing ASLR and adding write permission."""
    pe = bytearray(data)
    pe_offset = int.from_bytes(pe[0x3C:0x40], "little")

    # Clear DYNAMIC_BASE from DllCharacteristics (PE offset + 0x5E, 2 bytes)
    dll_char_offset = pe_offset + 0x5E
    dll_char = int.from_bytes(pe[dll_char_offset : dll_char_offset + 2], "little")
    pe[dll_char_offset : dll_char_offset + 2] = struct.pack("<H", dll_char & ~DLLCHAR_DYNAMIC_BASE)

    num_sections = int.from_bytes(pe[pe_offset + 0x06 : pe_offset + 0x08], "little")
    opt_header_size = int.from_bytes(pe[pe_offset + 0x14 : pe_offset + 0x16], "little")
    section_table_base = pe_offset + 0x18 + opt_header_size

    for i in range(num_sections):
        sec_off = section_table_base + (i * 0x28)
        name = pe[sec_off : sec_off + 8].rstrip(b"\x00")
        char_off = sec_off + 0x24
        char = int.from_bytes(pe[char_off : char_off + 4], "little")

        # bool(char & 0x20000000) IMAGE_SCN_MEM_EXECUTE
        # bool(char & 0x80000000) IMAGE_SCN_MEM_WRITE
        # is standard -> bytes(name) in STANDARD_SECTION_NAMES
        selected = (
            name == section_name
            if section_name is not None
            else bool(char & 0x20000000) and not bool(char & 0x80000000) and bytes(name) not in STANDARD_SECTION_NAMES
        )
        if selected:
            pe[char_off : char_off + 4] = struct.pack("<I", char | 0x80000000)

    return pe
