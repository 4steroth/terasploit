from teralibs.tsf.terax.nops.base import FixedWidthNop


class Sparc32Nop(FixedWidthNop):
    """Generate the SPARC SETHI 0, %g0 NOP instruction."""

    default_strategy = "fixed-width"
    name = "sparc"
    instruction = b"\x01\x00\x00\x00"
    alignment = 4
    default_byteorder = "big"
    byteorders = ("big",)


class Sparc64Nop(Sparc32Nop):
    """Generate the SPARC V9 SETHI 0, %g0 NOP instruction."""

    default_strategy = "fixed-width"
    name = "sparc64"
