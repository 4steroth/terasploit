# CORE ARCHITECTURE CONSTANTS & CONFIGURATIONS (lib/rex/arch.rb)

ARCH_X86 = "x86"
ARCH_X86_64 = "x86_64"
ARCH_X64 = "x64"  # Used for compatibility mapping alongside x86_64
ARCH_MIPS = "mips"
ARCH_MIPSLE = "mipsle"
ARCH_MIPSBE = "mipsbe"
ARCH_MIPS64 = "mips64"
ARCH_MIPS64LE = "mips64le"
ARCH_PPC = "ppc"
ARCH_PPCE500V2 = "ppce500v2"
ARCH_PPC64 = "ppc64"
ARCH_PPC64LE = "ppc64le"
ARCH_CBEA = "cbea"
ARCH_CBEA64 = "cbea64"
ARCH_SPARC = "sparc"
ARCH_SPARC64 = "sparc64"
ARCH_ARMLE = "armle"
ARCH_ARMBE = "armbe"
ARCH_AARCH64 = "aarch64"
ARCH_ZARCH = "zarch"
ARCH_CMD = "cmd"
ARCH_BASH = "bash"
ARCH_PYTHON = "python"
ARCH_RUBY = "ruby"
ARCH_PERL = "perl"
ARCH_JAVA = "java"
ARCH_PHP = "php"
ARCH_NODEJS = "nodejs"
ARCH_LUA = "lua"
ARCH_TTY = "tty"

# High-level architecture catalog matching framework scopes
ARCH_ALL = "all"

# Endianness Mapping Tokens
ENDIAN_LITTLE = "little"
ENDIAN_BIG = "big"

# Direct lookups for architecture endianness
_LITTLE_ENDIAN_ARCHS = {
    ARCH_X86,
    ARCH_X86_64,
    ARCH_X64,
    ARCH_MIPSLE,
    ARCH_MIPS64LE,
    ARCH_PPC64LE,
    ARCH_ARMLE,
    ARCH_AARCH64,
}


def endian(arch: str) -> str:
    """
    Returns the target byte ordering (endianness) for a specified architecture token.
    """
    return ENDIAN_LITTLE if arch in _LITTLE_ENDIAN_ARCHS else ENDIAN_BIG
