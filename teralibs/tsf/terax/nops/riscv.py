from teralibs.tsf.terax.nops.base import FixedWidthNop


class RiscV32Nop(FixedWidthNop):
    """Generate the 32-bit ADDI x0, x0, 0 RISC-V NOP instruction."""

    default_strategy = "fixed-width"
    name = "riscv32"
    instruction = b"\x13\x00\x00\x00"
    alignment = 4
    default_byteorder = "little"
    byteorders = ("little",)


class RiscV64Nop(RiscV32Nop):
    """Generate the 32-bit ADDI x0, x0, 0 RISC-V NOP instruction."""

    default_strategy = "fixed-width"
    name = "riscv64"
