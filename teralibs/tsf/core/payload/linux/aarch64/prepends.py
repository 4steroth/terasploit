import contextlib
from collections.abc import Sequence


def _insn(value):
    """Pack a 32-bit AArch64 instruction word as little-endian bytes."""
    return value.to_bytes(4, "little")


# Pre-encoded instruction sequences


# MOVZ Xd, #imm16  →  0xD2800008 | (imm16 << 5)  for x8 (syscall number)
def _movz_x8(imm):
    return _insn(0xD2800008 | ((imm & 0xFFFF) << 5))


# mov x0, #0  (MOVZ x0, 0)
_MOV_X0_0 = _insn(0xD2800000)  # movz x0, #0
# mov x1, #0
_MOV_X1_0 = _insn(0xD2800020)  # movz x1, #0
# mov x2, #0
_MOV_X2_0 = _insn(0xD2800040)  # movz x2, #0
# svc #0
_SVC_0 = _insn(0xD4000001)  # svc  #0


# cbz x0, +offset  - "compare and branch if zero"
# Encoding (CBZ Xt, label): 0xB4000000 | (imm19 << 5) | Xt
# offset in bytes, must be a multiple of 4; imm19 = offset/4
def _cbz_x0(byte_offset):
    imm19 = (byte_offset // 4) & 0x7FFFF
    return _insn(0xB4000000 | (imm19 << 5) | 0)


# Mix-in class


class LinuxAarch64Prepends:
    """Mixin that exposes Linux AArch64 prepend/append stubs as instance attributes."""

    #: Prepend application order - mirrors prepends_order in prepends.rb.
    #: All seven uid/gid stubs are listed so that operators can enable any
    #: combination; apply_prepends() silently skips those not set in ctx.
    PREPENDS_ORDER: Sequence[str] = [
        "PrependFork",
        "PrependSetresuid",
        "PrependSetreuid",
        "PrependSetuid",
        "PrependSetresgid",
        "PrependSetregid",
        "PrependSetgid",
    ]

    #: Append application order.
    #: AppendExit is intentionally absent here (see module docstring);
    #: exit-stub appending is driven by the EXITFUNC option in apply_prepends().
    APPENDS_ORDER: Sequence = []

    def appends_map(self):
        """Append stubs mapping."""
        return {
            # exit(0): x0=0, x8=93(__NR_exit), svc #0
            "AppendExit": (
                _MOV_X0_0  # movz x0, #0
                + _movz_x8(93)  # movz x8, #93  ; __NR_exit
                + _SVC_0  # svc  #0
            ),
        }

    def prepends_map(self):
        """Prepend stubs mapping."""

        # AArch64 Linux does not expose fork(2) / vfork(2) as bare syscalls.
        # The canonical way to fork is clone(SIGCHLD, 0):
        #   __NR_clone  = 220
        #   __NR_setsid = 157
        #   __NR_exit   =  93
        #   SIGCHLD     = 0x11

        # clone(SIGCHLD, 0): x0=0x11, x1=0, x8=220, svc #0
        _clone_sigchld = (
            _insn(0xD2800220)  # movz x0, #0x11   ; SIGCHLD
            + _MOV_X1_0  # movz x1, #0
            + _movz_x8(220)  # movz x8, #220    ; __NR_clone
            + _SVC_0  # svc  #0
        )
        # After clone: x0 == 0 in child, >0 in parent.
        _exit0 = (
            _MOV_X0_0  # movz x0, #0
            + _movz_x8(93)  # movz x8, #93     ; __NR_exit
            + _SVC_0  # svc  #0
        )
        # setsid(): x8=157, svc #0  (x0 unused as arg)
        _setsid = (
            _movz_x8(157)  # movz x8, #157    ; __NR_setsid
            + _SVC_0  # svc  #0
        )

        # PrependFork sequence:
        #   clone(SIGCHLD,0)  ; x0 = child_pid / 0
        #   cbz  x0, child1   ; if child: skip exit
        #   exit(0)           ; parent exits
        # child1:
        #   setsid()
        #   clone(SIGCHLD,0)  ; x0 = child_pid2 / 0
        #   cbz  x0, child2   ; if child2: skip exit
        #   exit(0)           ; intermediate child exits
        # child2: (continues into payload)

        sz_exit0 = len(_exit0)  # 12 bytes - how far each cbz must jump

        prepend_fork = (
            _clone_sigchld  # clone(SIGCHLD,0)
            + _cbz_x0(sz_exit0)  # cbz x0, child1   ; skip exit0 (12 bytes)
            + _exit0  # exit(0)  [parent]
            # child1:
            + _setsid  # setsid()
            + _clone_sigchld  # clone(SIGCHLD,0)
            + _cbz_x0(sz_exit0)  # cbz x0, child2   ; skip exit0 (12 bytes)
            + _exit0  # exit(0)  [intermediate]
            # child2: falls through into payload
        )

        return {
            "PrependFork": prepend_fork,
            # setresuid(0, 0, 0): __NR_setresuid = 164
            "PrependSetresuid": (
                _MOV_X0_0  # movz x0, #0  ; ruid
                + _MOV_X1_0  # movz x1, #0  ; euid
                + _MOV_X2_0  # movz x2, #0  ; suid
                + _movz_x8(164)  # movz x8, #164 ; __NR_setresuid
                + _SVC_0  # svc  #0
            ),
            # setreuid(0, 0): __NR_setreuid = 145
            "PrependSetreuid": (
                _MOV_X0_0  # movz x0, #0  ; ruid
                + _MOV_X1_0  # movz x1, #0  ; euid
                + _movz_x8(145)  # movz x8, #145 ; __NR_setreuid
                + _SVC_0  # svc  #0
            ),
            # setuid(0): __NR_setuid = 146
            "PrependSetuid": (
                _MOV_X0_0  # movz x0, #0
                + _movz_x8(146)  # movz x8, #146 ; __NR_setuid
                + _SVC_0  # svc  #0
            ),
            # setresgid(0, 0, 0): __NR_setresgid = 165
            "PrependSetresgid": (
                _MOV_X0_0  # movz x0, #0  ; rgid
                + _MOV_X1_0  # movz x1, #0  ; egid
                + _MOV_X2_0  # movz x2, #0  ; sgid
                + _movz_x8(165)  # movz x8, #165 ; __NR_setresgid
                + _SVC_0  # svc  #0
            ),
            # setregid(0, 0): __NR_setregid = 143
            "PrependSetregid": (
                _MOV_X0_0  # movz x0, #0  ; rgid
                + _MOV_X1_0  # movz x1, #0  ; egid
                + _movz_x8(143)  # movz x8, #143 ; __NR_setregid
                + _SVC_0  # svc  #0
            ),
            # setgid(0): __NR_setgid = 144
            "PrependSetgid": (
                _MOV_X0_0  # movz x0, #0
                + _movz_x8(144)  # movz x8, #144 ; __NR_setgid
                + _SVC_0  # svc  #0
            ),
        }

    def apply_prepends(self, shellcode, ctx):
        """Prepend and append selected stubs to *shellcode*."""
        prefix = b""
        suffix = b""

        for key in self.PREPENDS_ORDER:
            with contextlib.suppress(Exception):
                if ctx.get_option(key):
                    prefix += self.prepends_map()[key]

        for key in self.APPENDS_ORDER:
            with contextlib.suppress(Exception):
                if ctx.get_option(key):
                    suffix += self.appends_map()[key]

        result = prefix + shellcode + suffix

        # EXITFUNC stub - appended last so it wraps the entire payload.
        exitfunc = ""
        with contextlib.suppress(Exception):
            raw = ctx.get_option("EXITFUNC") or ""
            exitfunc = str(raw).lower().strip()

        if exitfunc in ("process", "thread"):
            # exit(0): movz x0, #0; movz x8, #93; svc #0
            result += (
                _MOV_X0_0  # movz x0, #0
                + _movz_x8(93)  # movz x8, #93  ; __NR_exit
                + _SVC_0  # svc  #0
            )
        # exitfunc == "none" or unrecognised → no stub appended

        return result
