import contextlib
from collections.abc import Sequence


class LinuxX64Prepends:
    """
    Mixin that exposes Linux x64 prepend/append stubs as instance attributes
    and provides apply_prepends() to wrap a generated payload with the
    stubs selected by the user's option values.
    """

    # Order in which prepends/appends are applied

    #: Prepend application order - mirrors prepends_order in prepends.rb
    PREPENDS_ORDER: Sequence[str] = [
        "PrependFork",
        "PrependSetresuid",
        "PrependSetreuid",
        "PrependSetuid",
        "PrependSetresgid",
        "PrependSetregid",
        "PrependSetgid",
    ]

    #: Append application order - now includes AppendExit for symmetry
    APPENDS_ORDER: Sequence[str] = [
        "AppendExit",
    ]

    def appends_map(self):
        """Append application mapping."""
        return {
            # exit(0) - syscall 0x3c (60)
            "AppendExit": (
                b"\x48\x31\xff"  # xor    rdi,rdi
                b"\x6a\x3c"  # push   0x3c
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
            ),
        }

    def prepends_map(self):
        """Prepends application mapping."""
        return {
            # Double-fork into a background daemon session.
            # fork() -> if parent: exit(0); setsid(); fork() -> if parent: exit(0)
            "PrependFork": (
                b"\x6a\x39"  # push   57        ; __NR_fork
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
                b"\x48\x85\xc0"  # test   rax,rax
                b"\x74\x08"  # jz     loc_0012
                # loc_000a:
                b"\x48\x31\xff"  # xor    rdi,rdi
                b"\x6a\x3c"  # push   60        ; __NR_exit
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
                # loc_0012:
                b"\x04\x70"  # add    al, 112   ; __NR_setsid
                b"\x0f\x05"  # syscall
                b"\x6a\x39"  # push   57        ; __NR_fork
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
                b"\x48\x85\xc0"  # test   rax,rax
                b"\x75\xea"  # jnz    loc_000a
            ),
            # setresuid(0, 0, 0) -> syscall 0x75 (117)
            "PrependSetresuid": (
                b"\x48\x31\xff"  # xor    rdi,rdi
                b"\x48\x89\xfe"  # mov    rsi,rdi
                b"\x48\x89\xf2"  # mov    rdx,rsi     ; fixed: ensure suid is 0
                b"\x6a\x75"  # push   0x75
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
            ),
            # setreuid(0, 0) -> syscall 0x71 (113)
            "PrependSetreuid": (
                b"\x48\x31\xff"  # xor    rdi,rdi
                b"\x48\x89\xfe"  # mov    rsi,rdi
                b"\x48\x89\xf2"  # mov    rdx,rsi
                b"\x6a\x71"  # push   0x71
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
            ),
            # setuid(0) -> syscall 0x69 (105)
            "PrependSetuid": (
                b"\x48\x31\xff"  # xor    rdi,rdi
                b"\x6a\x69"  # push   0x69
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
            ),
            # setresgid(0, 0, 0) -> syscall 0x77 (119)
            "PrependSetresgid": (
                b"\x48\x31\xff"  # xor    rdi,rdi
                b"\x48\x89\xfe"  # mov    rsi,rdi
                b"\x48\x89\xf2"  # mov    rdx,rsi     ; fixed: ensure sgid is 0
                b"\x6a\x77"  # push   0x77
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
            ),
            # setregid(0, 0) -> syscall 0x72 (114)
            "PrependSetregid": (
                b"\x48\x31\xff"  # xor    rdi,rdi
                b"\x48\x89\xfe"  # mov    rsi,rdi
                b"\x48\x89\xf2"  # mov    rdx,rsi
                b"\x6a\x72"  # push   0x72
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
            ),
            # setgid(0) -> syscall 0x6a (106)
            "PrependSetgid": (
                b"\x48\x31\xff"  # xor    rdi,rdi
                b"\x6a\x6a"  # push   0x6a
                b"\x58"  # pop    rax
                b"\x0f\x05"  # syscall
            ),
        }

    def apply_prepends(self, shellcode, ctx):
        """
        Prepend and append selected stubs to *shellcode*.

        Reads prepend/append option values from *ctx* via
        ctx.get_option(name).  If the option value is truthy the
        corresponding stub is included.
        """
        prefix = b""
        suffix = b""

        # Resolve maps once
        p_map = self.prepends_map()
        a_map = self.appends_map()

        for key in self.PREPENDS_ORDER:
            with contextlib.suppress(Exception):
                if ctx.get_option(key):
                    prefix += p_map[key]

        for key in self.APPENDS_ORDER:
            with contextlib.suppress(Exception):
                if ctx.get_option(key):
                    suffix += a_map[key]

        result = prefix + shellcode + suffix

        # EXITFUNC stub - appended last so it wraps the entire payload.
        exitfunc = ""
        with contextlib.suppress(Exception):
            raw = ctx.get_option("EXITFUNC") or ""
            exitfunc = str(raw).lower().strip()

        if exitfunc in ("process", "thread"):
            # sys_exit(0): push 0x3c; pop rax; xor rdi,rdi; syscall
            result += (
                b"\x6a\x3c"  # push  0x3c    ; __NR_exit = 60
                b"\x58"  # pop   rax
                b"\x48\x31\xff"  # xor   rdi, rdi  ; status = 0
                b"\x0f\x05"  # syscall
            )

        return result
