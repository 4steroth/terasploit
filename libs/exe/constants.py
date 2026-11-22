# Section alignment boundaries
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x0200

# Machine architecture identifiers
MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664

# Optional Header DllCharacteristics flags
DLLCHAR_DYNAMIC_BASE = 0x0040
DLLCHAR_HIGH_ENTROPY_VA = 0x0020

# Section characteristic flags
SECTION_EXECUTE_READ = 0x60000020
SECTION_EXECUTE_READ_WRITE = 0xE0000020

# Standard PE section names (excluded from auto-detection in patch)
STANDARD_SECTION_NAMES = {
    b".text",
    b".rdata",
    b".data",
    b".bss",
    b".reloc",
    b".rsrc",
    b".pdata",
    b".edata",
}
