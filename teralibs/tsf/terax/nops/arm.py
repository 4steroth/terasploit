import dataclasses

from teralibs.tsf.terax.nops.base import FixedWidthNop


@dataclasses.dataclass
class ArmA32Nop(FixedWidthNop):
    """Generate the A32 MOV r0, r0 NOP-equivalent instruction."""

    default_strategy = "fixed-width"
    name = "arm-a32"
    instruction = b"\x00\x00\xa0\xe1"
    alignment = 4
    default_byteorder = "little"


@dataclasses.dataclass
class ThumbNop(FixedWidthNop):
    """Generate the Thumb NOP instruction."""

    default_strategy = "fixed-width"
    name = "thumb"
    instruction = b"\x00\xbf"
    alignment = 2
    default_byteorder = "little"


@dataclasses.dataclass
class Thumb2Nop(ThumbNop):
    """Generate the 16-bit Thumb-2 NOP instruction."""

    default_strategy = "fixed-width"
    name = "thumb2"
