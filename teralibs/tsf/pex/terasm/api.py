import re
from collections.abc import Mapping

from teralibs.terasploit.framework.services.printf import print_line

# Import the Terasm abstractions
from teralibs.tsf.pex.terasm.package import (
    CPU,
    TA_ARCH_ARM,
    TA_ARCH_ARM64,
    TA_ARCH_EVM,
    TA_ARCH_HEXAGON,
    TA_ARCH_MIPS,
    TA_ARCH_PPC,
    TA_ARCH_SPARC,
    TA_ARCH_SYSTEMZ,
    # Architectures
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
    Assembler,
    TerasmError,
)


class Terasm:
    """A wrapper around the terasm Assembler to facilitate easy shellcode generation for the Terasploit framework."""

    # Comprehensive mapping of all supported Keystone architectures.
    ARCH_MAP: Mapping[str, int] = {
        "x86": TA_ARCH_X86,
        "arm": TA_ARCH_ARM,
        "arm64": TA_ARCH_ARM64,
        "mips": TA_ARCH_MIPS,
        "ppc": TA_ARCH_PPC,
        "sparc": TA_ARCH_SPARC,
        "systemz": TA_ARCH_SYSTEMZ,
        "hexagon": TA_ARCH_HEXAGON,
        "evm": TA_ARCH_EVM,
    }

    MODE_MAP: Mapping[str, int] = {
        "16": TA_MODE_16,
        "32": TA_MODE_32,
        "64": TA_MODE_64,
        "arm": TA_MODE_ARM,
        "thumb": TA_MODE_THUMB,
        "micro": TA_MODE_MICRO,
        "mips3": TA_MODE_MIPS3,
        "mips32r6": TA_MODE_MIPS32R6,
        "mips32": TA_MODE_MIPS32,
        "mips64": TA_MODE_MIPS64,
        "v8": TA_MODE_V8,
        "v9": TA_MODE_V9,
    }

    SYNTAX_MAP: Mapping[str, int] = {
        "intel": TA_OPT_SYNTAX_INTEL,
        "att": TA_OPT_SYNTAX_ATT,
        "nasm": TA_OPT_SYNTAX_NASM,
        "masm": TA_OPT_SYNTAX_MASM,
        "gas": TA_OPT_SYNTAX_GAS,
        "radix16": TA_OPT_SYNTAX_RADIX16,
    }

    def __init__(self, arch: str, mode: int, syntax: str = "intel", endian: str = "le"):
        """Initialise the assembler with the given CPU architecture settings."""
        self.arch_str = arch
        self.mode = mode
        self.syntax_str = syntax
        self.endian_str = endian

        # Determine the CPU configuration
        # Assuming CPU class methods like CPU.x86(), CPU.arm(), etc.
        self.cpu = self._get_cpu_config()
        self.assembler = Assembler(self.cpu)

    def _get_cpu_config(self) -> CPU:
        """Map strings to terasm CPU configuration."""
        if self.arch_str == "x86":
            return CPU.x86(self.mode, syntax=self.syntax_str)
        if self.arch_str == "arm":
            return CPU.arm(thumb=self.mode == 16)

        raise ValueError(f"Unsupported architecture/configuration: {self.arch_str}")

    def assemble_string(self, asm_code: str) -> bytes:
        """Assemble a string of instructions using the terasm Assembler."""
        try:
            # Using the terasm.Assembler.assemble method
            result = Assembler.assemble(self.cpu, asm_code)
            return result.data

        except TerasmError as e:
            print_line(f"[-] Assembly Error: {e}")
            return b""

    def assemble_file(self, filepath: str, fmt: str = "hex") -> str:
        """Read and assemble instructions from file."""
        try:
            with open(filepath, encoding="UTF-8") as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

            raw_bytes = self.assemble_string("; ".join(lines))
            return self.format_output(raw_bytes, fmt) if raw_bytes else ""

        except FileNotFoundError:
            print_line(f"[-] File not found: {filepath}")
            return ""

    def assemble(self, asm_code: str, addr: int = 0) -> bytes:
        """Entry point."""
        try:
            asm = Terasm._strip_asm_comments(asm_code) if self.syntax_str in ("intel") else asm_code
            result = Assembler.assemble(self.cpu, asm, addr)
            return result.data

        except TerasmError as e:
            print_line(f"[-] Assembly Error: {e}")
            return b""

    @staticmethod
    def format_output(data: bytes, fmt: str = "hex") -> str:
        """Format raw bytes to desired output format."""
        if fmt == "c":
            return "".join([f"\\x{b:02x}" for b in data])
        if fmt == "python":
            hex_part = "".join([f"\\x{b:02x}" for b in data])
            return f'shellcode = b"{hex_part}"'
        return data.hex()

    @staticmethod
    def _strip_asm_comments(asm: str) -> str:
        """Remove ; comments from assembly lines."""
        lines = asm.splitlines()
        cleaned = [re.sub(r";.*$", "", line).rstrip() for line in lines]
        return "\n".join([line for line in cleaned if line])
