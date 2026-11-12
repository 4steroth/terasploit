from teralibs.tsf.terax.nops.aarch64 import AArch64Nop
from teralibs.tsf.terax.nops.arm import ArmA32Nop, Thumb2Nop, ThumbNop
from teralibs.tsf.terax.nops.mips import Mips32Nop, Mips64Nop
from teralibs.tsf.terax.nops.powerpc import PowerPC32Nop, PowerPC64Nop
from teralibs.tsf.terax.nops.riscv import RiscV32Nop, RiscV64Nop
from teralibs.tsf.terax.nops.sparc import Sparc32Nop, Sparc64Nop
from teralibs.tsf.terax.nops.x64 import X64Nop
from teralibs.tsf.terax.nops.x86 import X86Nop


NOP_REGISTRY = {
    "x86": X86Nop,
    "i386": X86Nop,
    "x64": X64Nop,
    "x86_64": X64Nop,
    "amd64": X64Nop,
    "arm-a32": ArmA32Nop,
    "a32": ArmA32Nop,
    "thumb": ThumbNop,
    "thumb2": Thumb2Nop,
    "arm": Thumb2Nop,  # Retain Terax's historical ARM-as-Thumb2 alias.
    "arm64": AArch64Nop,
    "aarch64": AArch64Nop,
    "mips": Mips32Nop,
    "mips32": Mips32Nop,
    "mips64": Mips64Nop,
    "mipsel": Mips32Nop,
    "mipsle": Mips32Nop,
    "mipsbe": Mips32Nop,
    "mips64el": Mips64Nop,
    "mips64le": Mips64Nop,
    "mips64be": Mips64Nop,
    "powerpc": PowerPC32Nop,
    "ppc": PowerPC32Nop,
    "powerpc32": PowerPC32Nop,
    "ppc32": PowerPC32Nop,
    "ppcle": PowerPC32Nop,
    "ppcbe": PowerPC32Nop,
    "powerpc32le": PowerPC32Nop,
    "powerpc32be": PowerPC32Nop,
    "powerpc64": PowerPC64Nop,
    "ppc64": PowerPC64Nop,
    "ppc64le": PowerPC64Nop,
    "ppc64be": PowerPC64Nop,
    "powerpc64le": PowerPC64Nop,
    "powerpc64be": PowerPC64Nop,
    "sparc": Sparc32Nop,
    "sparc32": Sparc32Nop,
    "sparc64": Sparc64Nop,
    "riscv": RiscV32Nop,
    "riscv32": RiscV32Nop,
    "riscv64": RiscV64Nop,
}
