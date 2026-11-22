from typing import Any


class ExitfunkX86:
    """Implements arbitrary exit routines for Windows payloads."""

    def asm_exitfunk(self, opts: dict | None = None, block_api_hash: Any = None) -> str:
        """Generates assembly to trigger an unhandled exception for termination."""

        asm = """
            exitfunk:
                pop eax                 ; won't be returning, realign the stack with a pop
        """

        case = None
        if opts:
            case = opts.get("exitfunk")

        if case == "seh":
            asm += f"""
                mov ebx, {block_api_hash("kernel32.dll", "SetUnhandledExceptionFilter")}
                push byte 0             ; push the exit function parameter
                push ebx                ; push the hash of the exit function
                call ebp                ; SetUnhandledExceptionFilter(0)
                push byte 0
                ret                     ; Return to NULL (crash)
            """

        if case == "thread":
            asm += f"""
                mov ebx, {block_api_hash("kernel32.dll", "ExitThread")}
                push {block_api_hash("kernel32.dll", "GetVersion")}

                call ebp               ; GetVersion(); (AL will = major version and AH will = minor version)
                cmp al, 6              ; If we are not running on Windows Vista, 2008 or 7
                jl exitfunk_goodbye    ; Then just call the exit function...
                cmp bl, 0xE0           ; If we are trying a call to kernel32.dll!ExitThread on Windows Vista, 2008 or 7...
                jne exitfunk_goodbye

                mov ebx, {block_api_hash("ntdll.dll", "RtlExitUserThread")}

            exitfunk_goodbye:          ; We now perform the actual call to the exit function
                push byte 0              ; push the exit function parameter
                push ebx               ; push the hash of the exit function
                call ebp               ; call ExitThread(0) || RtlExitUserThread(0)
            """

        if case in ("process", None):
            asm += f"""
                mov ebx, {block_api_hash("kernel32.dll", "ExitProcess")}
                push byte 0              ; push the exit function parameter
                push ebx               ; push the hash of the exit function
                call ebp               ; ExitProcess(0)
            """

        if case == "sleep":
            asm += f"""
                mov ebx, {block_api_hash("kernel32.dll", "Sleep")}
                push 300000            ; 300 seconds
                push ebx               ; push the hash of the function
                call ebp               ; Sleep(300000)
                jmp exitfunk           ; repeat
            """

        return asm

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(Architecture={'x86'!r})"
