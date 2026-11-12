from teralibs.tsf.terax.nops.base import FixedWidthNop


class PowerPC32Nop(FixedWidthNop):
    """Generate the PowerPC ORI r0, r0, 0 NOP instruction."""

    default_strategy = "fixed-width"
    name = "powerpc"
    instruction = b"\x60\x00\x00\x00"
    alignment = 4
    default_byteorder = "big"


class PowerPC64Nop(PowerPC32Nop):
    """Generate the PowerPC64 ORI r0, r0, 0 NOP instruction."""

    default_strategy = "fixed-width"
    name = "powerpc64"
