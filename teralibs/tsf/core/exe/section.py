import struct
from dataclasses import dataclass

from teralibs.tsf.core.exe.constants import FILE_ALIGNMENT
from teralibs.tsf.core.exe.utils import align


@dataclass
class SectionHeader:
    """Holds the fields needed to write a PE section header entry."""

    name: bytes
    virtual_size: int
    virtual_addr: int
    raw_size: int
    raw_offset: int
    characteristics: int


def compute_bounds(pe: bytearray, pe_offset: int) -> tuple[int, int, int]:
    """Returns the file end boundary and the last section's virtual address and virtual size."""
    num_sections = struct.unpack_from("<H", pe, pe_offset + 6)[0]
    opt_header_size = struct.unpack_from("<H", pe, pe_offset + 20)[0]
    section_table = pe_offset + 24 + opt_header_size

    file_end = len(pe)
    last_va = 0
    last_vs = 0

    for i in range(num_sections):
        offset = section_table + (i * 40)
        va = struct.unpack_from("<I", pe, offset + 12)[0]
        vs = struct.unpack_from("<I", pe, offset + 8)[0]
        raw_off = struct.unpack_from("<I", pe, offset + 20)[0]
        raw_sz = struct.unpack_from("<I", pe, offset + 16)[0]

        file_end = max(file_end, raw_off + raw_sz)
        if va > last_va:
            last_va = va
            last_vs = vs

    return file_end, last_va, last_vs


def write(pe: bytearray, slot: int, header: SectionHeader) -> None:
    """Serializes a SectionHeader into a 40-byte entry at the given slot offset."""
    pe[slot : slot + 40] = (
        header.name.ljust(8, b"\x00")
        + struct.pack("<I", header.virtual_size)
        + struct.pack("<I", header.virtual_addr)
        + struct.pack("<I", header.raw_size)
        + struct.pack("<I", header.raw_offset)
        + b"\x00" * 12
        + struct.pack("<I", header.characteristics)
    )


def accommodate(pe: bytearray, pe_offset: int, payload_file_offset: int) -> tuple[bytearray, int, int]:
    """Grows SizeOfHeaders if needed to fit a new section entry, shifting body data forward."""
    opt_header_size = struct.unpack_from("<H", pe, pe_offset + 20)[0]
    num_sections = struct.unpack_from("<H", pe, pe_offset + 6)[0]
    section_table = pe_offset + 24 + opt_header_size
    hdr_size_offset = pe_offset + 24 + 60

    slot_start = section_table + num_sections * 40
    current_header_size = struct.unpack_from("<I", pe, hdr_size_offset)[0]

    if slot_start + 40 > current_header_size:
        new_header_size = align(slot_start + 40, FILE_ALIGNMENT)
        struct.pack_into("<I", pe, hdr_size_offset, new_header_size)

        shift = new_header_size - current_header_size
        pe = bytearray(pe[:current_header_size] + (b"\x00" * shift) + pe[current_header_size:])
        payload_file_offset += shift

        for i in range(num_sections):
            s_off = section_table + (i * 40)
            raw_off = struct.unpack_from("<I", pe, s_off + 20)[0]
            struct.pack_into("<I", pe, s_off + 20, raw_off + shift)

    return pe, slot_start, payload_file_offset


def increment_count(pe: bytearray, pe_offset: int) -> None:
    """Increments the COFF header section count by one."""
    struct.pack_into("<H", pe, pe_offset + 6, struct.unpack_from("<H", pe, pe_offset + 6)[0] + 1)
