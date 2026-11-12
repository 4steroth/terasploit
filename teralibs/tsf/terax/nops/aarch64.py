import dataclasses

from teralibs.tsf.terax.nops.base import FixedWidthNop


@dataclasses.dataclass
class AArch64Nop(FixedWidthNop):
    """Generate the AArch64 HINT #0 NOP instruction."""

    default_strategy = "fixed-width"
    name = "aarch64"
    instruction = b"\x1f\x20\x03\xd5"
    alignment = 4
    default_byteorder = "little"
