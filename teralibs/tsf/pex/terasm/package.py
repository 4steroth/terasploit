# terasm - A metasm-inspired assembler API built on libkeystone.so.
#
# terasm is a standalone Python module that wraps libkeystone.so with a
# clean, object-oriented API modelled after the metasm framework. The
# underlying assembler engine is keystone-engine; terasm provides its own
# public interface without exposing keystone internals.
#
# Basic usage:
#
#   from terasm import Assembler, CPU
#
#   result = Assembler.assemble(CPU.x86(32), "mov eax, 1; ret")
#   print(result.hex)         # "b801000000c3"
#   print(result.data)        # b'\xb8\x01\x00\x00\x00\xc3'
#   print(result.insn_count)  # 2
#
#   # Persistent handle with sym_resolver:
#   with Assembler(CPU.x86(64)) as asm:
#       asm.sym_resolver = my_resolver
#       result = asm.asm("call my_symbol", addr=0x1000)

from teralibs.tsf.pex.terasm import engine as _engine
from teralibs.tsf.pex.terasm.assembler import Assembler, EncodedData, TerasmError
from teralibs.tsf.pex.terasm.cpu import CPU
from teralibs.tsf.pex.terasm.terasm_const import (
    TA_API_MAJOR,
    TA_API_MINOR,
    # Architectures
    TA_ARCH_ARM,
    TA_ARCH_ARM64,
    TA_ARCH_EVM,
    TA_ARCH_HEXAGON,
    TA_ARCH_MIPS,
    TA_ARCH_PPC,
    TA_ARCH_SPARC,
    TA_ARCH_SYSTEMZ,
    TA_ARCH_X86,
    # Modes
    TA_MODE_16,
    TA_MODE_32,
    TA_MODE_64,
    TA_MODE_ARM,
    TA_MODE_MICRO,
    TA_MODE_MIPS3,
    TA_MODE_MIPS32,
    TA_MODE_MIPS32R6,
    TA_MODE_MIPS64,
    TA_MODE_THUMB,
    TA_MODE_V8,
    TA_MODE_V9,
    TA_OPT_SYNTAX_ATT,
    TA_OPT_SYNTAX_GAS,
    # Syntax Options
    TA_OPT_SYNTAX_INTEL,
    TA_OPT_SYNTAX_MASM,
    TA_OPT_SYNTAX_NASM,
    TA_OPT_SYNTAX_RADIX16,
)


__all__ = [
    "CPU",
    # Architectures
    "TA_ARCH_ARM",
    "TA_ARCH_ARM64",
    "TA_ARCH_EVM",
    "TA_ARCH_HEXAGON",
    "TA_ARCH_MIPS",
    "TA_ARCH_PPC",
    "TA_ARCH_SPARC",
    "TA_ARCH_SYSTEMZ",
    "TA_ARCH_X86",
    # Modes
    "TA_MODE_16",
    "TA_MODE_32",
    "TA_MODE_64",
    "TA_MODE_ARM",
    "TA_MODE_MICRO",
    "TA_MODE_MIPS3",
    "TA_MODE_MIPS32",
    "TA_MODE_MIPS32R6",
    "TA_MODE_MIPS64",
    "TA_MODE_THUMB",
    "TA_MODE_V8",
    "TA_MODE_V9",
    # Syntax Options
    "TA_OPT_SYNTAX_ATT",
    "TA_OPT_SYNTAX_GAS",
    "TA_OPT_SYNTAX_INTEL",
    "TA_OPT_SYNTAX_MASM",
    "TA_OPT_SYNTAX_NASM",
    "TA_OPT_SYNTAX_RADIX16",
    "Assembler",
    "EncodedData",
    "TerasmError",
]


# Module-level convenience functions


def version():
    """Return the version of the loaded libkeystone.so as (major, minor, combined)."""
    return _engine.lib_version()


def arch_supported(arch):
    """Return True if the loaded libkeystone.so was compiled with support for the given TA_ARCH_* constant."""
    return _engine.arch_supported(arch)


def debug_info():
    """Return a diagnostic string listing supported architectures and library/binding version numbers. Useful for bug reports."""

    _archs = {
        "arm": TA_ARCH_ARM,
        "arm64": TA_ARCH_ARM64,
        "mips": TA_ARCH_MIPS,
        "sparc": TA_ARCH_SPARC,
        "systemz": TA_ARCH_SYSTEMZ,
        "ppc": TA_ARCH_PPC,
        "hexagon": TA_ARCH_HEXAGON,
        "x86": TA_ARCH_X86,
        "evm": TA_ARCH_EVM,
    }

    supported = "-".join(name for name in sorted(_archs) if arch_supported(_archs[name]))
    major, minor, _ = version()

    return f"terasm-{supported}-lib{major}.{minor}-api{TA_API_MAJOR}.{TA_API_MINOR}"
