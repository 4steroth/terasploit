from typing import Any


class ExitfunkX64:
    """Implements arbitrary exit routines for Windows payloads."""

    def asm_exitfunk(self, opts: dict | None = None, block_api_hash: Any = None) -> str:
        """Generates assembly to trigger an unhandled exception for termination."""

        asm = """
            exitfunk:
                pop rax                             ; won't be returning, realign the stack with a pop
        """

        case = None
        if opts:
            case = opts.get("exitfunk")

        if case == "seh":
            asm += f"""
                push 0
                pop rcx                             ; set the exit function parameter
                mov ebx, {block_api_hash("kernel32.dll", "SetUnhandledExceptionFilter")}
                mov r10d, ebx                       ; place the correct EXITFUNK into r10d
                call rbp                            ; SetUnhandledExceptionFilter(0)
                push 0
                ret                                 ; Return to NULL (crash)
            """

        if case == "thread":
            asm += f"""
                push 0
                pop rcx                             ; set the exit function parameter
                mov ebx, {block_api_hash("kernel32.dll", "ExitThread")}
                mov r10d, ebx                       ; place the correct EXITFUNK into r10d
                call rbp                            ; call EXITFUNK( 0 );
            """

        if case in ("process", None):
            asm += f"""
                push 0
                pop rcx                             ; set the exit function parameter
                mov r10d, {block_api_hash("kernel32.dll", "ExitProcess")}
                call rbp                            ; ExitProcess(0)
            """

        if case == "sleep":
            asm += f"""
                push 300000                         ; 300 seconds
                pop rcx                             ; set the sleep function parameter
                mov r10d, {block_api_hash("kernel32.dll", "Sleep")}
                call rbp                            ; Sleep(30000)
                jmp exitfunk                        ; repeat
            """

        return asm

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(Architecture={'x64'!r})"
