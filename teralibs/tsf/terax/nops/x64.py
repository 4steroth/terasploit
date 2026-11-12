from teralibs.tsf.terax.nops.x86 import X86Nop


class X64Nop(X86Nop):
    """Generate x86-64 NOP sequences using single- or multi-byte encodings."""

    name = "x64"
