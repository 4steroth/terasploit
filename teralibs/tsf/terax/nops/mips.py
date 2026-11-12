from teralibs.tsf.terax.nops.base import FixedWidthNop


class Mips32Nop(FixedWidthNop):
    """Generate the MIPS32 SLL $zero, $zero, 0 NOP instruction."""

    default_strategy = "fixed-width"
    name = "mips32"
    instruction = b"\x00\x00\x00\x00"
    alignment = 4
    default_byteorder = "big"


class Mips64Nop(Mips32Nop):
    """Generate the MIPS64 SLL $zero, $zero, 0 NOP instruction."""

    default_strategy = "fixed-width"
    name = "mips64"
