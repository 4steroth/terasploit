import contextlib
import random
import re
import struct
from collections.abc import Mapping


class ARCHX86:
    """X86 architecture."""

    # Register number constants
    EAX = AL = AX = ES = 0
    ECX = CL = CX = CS = 1
    EDX = DL = DX = SS = 2
    EBX = BL = BX = DS = 3
    ESP = AH = SP = FS = 4
    EBP = CH = BP = GS = 5
    ESI = DH = SI = 6
    EDI = BH = DI = 7

    reg_names32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
    reg_names16 = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di")
    reg_names8l = ("al", "cl", "dl", "bl", None, None, None, None)

    _registers: Mapping = {
        name: value
        for value, names in enumerate(
            (
                ("eax", "al", "ax", "es"),
                ("ecx", "cl", "cx", "cs"),
                ("edx", "dl", "dx", "ss"),
                ("ebx", "bl", "bx", "ds"),
                ("esp", "ah", "sp", "fs"),
                ("ebp", "ch", "bp", "gs"),
                ("esi", "dh", "si"),
                ("edi", "bh", "di"),
            )
        )
        for name in names
    }

    @staticmethod
    def _as_bytes(value):
        """Normalize supported binary input to immutable bytes."""
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return value.encode("latin-1")
        raise TypeError("Expected bytes, bytearray, or a Latin-1 string")

    @staticmethod
    def _byte(value):
        """Encode an integer as a single unsigned byte."""
        return bytes((value & 0xFF,))

    @staticmethod
    def _check_reg(*regs):
        """Validate that each register number is in the x86 range."""
        for reg in regs:
            if not isinstance(reg, int) or not 0 <= reg <= 7:
                raise ValueError(f"Invalid register {reg}")

    @staticmethod
    def _badchar_index(data, badchars):
        """Return the first index containing a forbidden byte."""
        data = ARCHX86._as_bytes(data)
        badchars = ARCHX86._as_bytes(badchars)
        for index, value in enumerate(data):
            if value in badchars:
                return index
        return None

    @staticmethod
    def _check_badchars(data, badchars=b""):
        """Reject data containing any forbidden byte."""
        data = ARCHX86._as_bytes(data)
        index = ARCHX86._badchar_index(data, badchars)
        if index is not None:
            raise RuntimeError(f"Bad character at {index}")
        return data

    @staticmethod
    def jmp_reg(reg):
        """Generate an indirect jump to the specified register."""
        if isinstance(reg, str):
            reg = ARCHX86.reg_number(reg)
        ARCHX86._check_reg(reg)
        return b"\xff" + ARCHX86._byte(0xE0 + reg)

    @staticmethod
    def loop(offset):
        """Generate a LOOP instruction with a relative offset."""
        return b"\xe2" + ARCHX86.pack_lsb(ARCHX86.rel_number(offset, -2))

    @staticmethod
    def jmp(addr):
        """Generate a near relative JMP instruction."""
        return b"\xe9" + ARCHX86.pack_dword(ARCHX86.rel_number(addr))

    @staticmethod
    def dword_adjust(dword, amount=0):
        """Adjust a little-endian 32-bit value by an integer amount."""
        dword = ARCHX86._as_bytes(dword)
        value = struct.unpack("<I", dword[:4])[0]
        return ARCHX86.pack_dword(value + amount)

    @staticmethod
    def searcher(tag):
        """Generate a tag-based memory search routine."""
        tag = ARCHX86._as_bytes(tag)
        return (
            b"\xbe"
            + ARCHX86.dword_adjust(tag, -1)  # mov esi, Tag - 1
            + b"\x46"  # inc esi
            + b"\x47"  # inc edi
            + b"\x39\x37"  # cmp [edi], esi
            + b"\x75\xfb"  # jnz end_search
            + b"\x46"  # inc esi
            + b"\x4f"  # dec edi
            + b"\x39\x77\xfc"  # cmp [edi-4], esi
            + b"\x75\xfa"  # jnz start_search
            + ARCHX86.jmp_reg("edi")
        )

    @staticmethod
    def copy_to_stack(length):
        """Generate a stub that copies following data onto the stack."""
        length = (length + 3) & ~0x3
        return (
            b"\xeb\x0f"  # jmp _end
            + ARCHX86.push_dword(length)  # push n
            + b"\x59"  # pop ecx
            + b"\x5e"  # pop esi
            + b"\x29\xcc"  # sub esp, ecx
            + b"\x89\xe7"  # mov edi, esp
            + b"\xf3\xa4"  # rep movsb
            + b"\xff\xe4"  # jmp esp
            + b"\xe8\xec\xff\xff\xff"  # call _start
        )

    @staticmethod
    def jmp_short(addr):
        """Generate a short relative JMP instruction."""
        return b"\xeb" + ARCHX86.pack_lsb(ARCHX86.rel_number(addr, -2))

    @staticmethod
    def call(addr):
        """Generate a relative CALL instruction."""
        return b"\xe8" + ARCHX86.pack_dword(ARCHX86.rel_number(addr, -5))

    @staticmethod
    def rel_number(num, delta=0):
        """Normalize a relative offset and apply its adjustment."""
        if isinstance(num, str):
            value = num
            if value.startswith("$+"):
                num = int(value[2:] or "0", 10)
            elif value.startswith("$-"):
                num = -int(value[2:] or "0", 10)
            elif value.startswith("0x"):
                num = int(value, 16)
            else:
                num = int(value, 10)
                delta = 0
        return int(num) + delta

    @staticmethod
    def reg_number(reg):
        """Return the numeric ID for a named register."""
        if isinstance(reg, int):
            return reg

        try:
            return ARCHX86._registers[reg.upper()]

        except KeyError, AttributeError:
            raise ValueError(f"Unknown register: {reg!r}") from None

    @staticmethod
    def reg_name32(num):
        """Return the 32-bit name for a register ID."""
        ARCHX86._check_reg(num)
        return ARCHX86.reg_names32[num]

    @staticmethod
    def encode_effective(shift, dst):
        """Encode the ModR/M effective-address register field."""
        return 0xC0 | (shift << 3) | dst

    @staticmethod
    def encode_modrm(dst, src):
        """Encode a register-to-register ModR/M byte."""
        ARCHX86._check_reg(dst, src)
        return ARCHX86._byte(0xC0 | src | (dst << 3))

    @staticmethod
    def push_byte(value):
        """Generate a PUSH instruction for a signed byte value."""
        if -128 <= value < 128:
            return b"\x6a" + ARCHX86._byte(value)
        raise ValueError("Can only take signed byte values!")

    @staticmethod
    def push_word(value):
        """Generate a PUSH instruction for a 16-bit value."""
        return b"\x66\x68" + ARCHX86.pack_word(value)

    @staticmethod
    def push_dword(value):
        """Generate a PUSH instruction for a 32-bit value."""
        return b"\x68" + ARCHX86.pack_dword(value)

    @staticmethod
    def pop_dword(dst):
        """Generate a POP instruction for a 32-bit register."""
        ARCHX86._check_reg(dst)
        return ARCHX86._byte(0x58 | dst)

    @staticmethod
    def clear(reg, badchars=b""):
        """Generate an instruction sequence that clears a register."""
        ARCHX86._check_reg(reg)
        return ARCHX86.instruction_set(reg, 0, badchars)

    @staticmethod
    def mov_byte(reg, value):
        """Generate a MOV instruction for a register's low byte."""
        ARCHX86._check_reg(reg)
        if not 0 <= value <= 0xFF:
            raise ValueError("Can only take unsigned byte values!")
        return ARCHX86._byte(0xB0 | reg) + ARCHX86._byte(value)

    @staticmethod
    def mov_word(reg, value):
        """Generate a MOV instruction for a 16-bit register value."""
        ARCHX86._check_reg(reg)
        if not 0 <= value <= 0xFFFF:
            raise ValueError("Can only take unsigned word values!")
        return b"\x66" + ARCHX86._byte(0xB8 | reg) + ARCHX86.pack_word(value)

    @staticmethod
    def mov_dword(reg, value):
        """Generate a MOV instruction for a 32-bit register value."""
        ARCHX86._check_reg(reg)
        return ARCHX86._byte(0xB8 | reg) + ARCHX86.pack_dword(value)

    # ARCHX86.set renamed to instruction_set
    @staticmethod
    def instruction_set(dst, value, badchars=b""):
        """Generate a register assignment using an available safe encoding."""
        ARCHX86._check_reg(dst)
        badchars = ARCHX86._as_bytes(badchars)

        # If the value is zero, try xor/sub dst, dst.
        if value == 0:
            opcodes = bytes(opcode for opcode in (0x29, 0x2B, 0x31, 0x33) if opcode not in badchars)
            if opcodes:
                opcode = random.choice(opcodes)
                return ARCHX86._byte(opcode) + ARCHX86.encode_modrm(dst, dst)

        # Try push BYTE value; pop dst.
        with contextlib.suppress(ValueError, RuntimeError, OverflowError):
            return ARCHX86._check_badchars(ARCHX86.push_byte(value) + ARCHX86.pop_dword(dst), badchars)

        # Try clear dst, then mov BYTE dst.
        with contextlib.suppress(ValueError, RuntimeError, OverflowError):
            if value != 0:
                return ARCHX86._check_badchars(
                    ARCHX86.clear(dst, badchars) + ARCHX86.mov_byte(dst, value),
                    badchars,
                )

        # Try mov DWORD dst.
        with contextlib.suppress(ValueError, RuntimeError, OverflowError):
            return ARCHX86._check_badchars(ARCHX86.mov_dword(dst, value), badchars)

        # Try push DWORD, pop dst.
        with contextlib.suppress(ValueError, RuntimeError, OverflowError):
            return ARCHX86._check_badchars(ARCHX86.push_dword(value) + ARCHX86.pop_dword(dst), badchars)

        # Try clear dst, then mov WORD dst.
        with contextlib.suppress(ValueError, RuntimeError, OverflowError):
            if value != 0:
                return ARCHX86._check_badchars(
                    ARCHX86.clear(dst, badchars) + ARCHX86.mov_word(dst, value),
                    badchars,
                )

        raise RuntimeError("No valid set instruction could be created!")

    @staticmethod
    def sub(value, reg, *, settings=()):
        """Generate an instruction sequence that subtracts a value from a register.

        >>> args: settings => is a tuple
        >>> contents: badchars=b"", add=False, adjust=False, bits=0
        """
        badchars, add, adjust, bits = settings

        ARCHX86._check_reg(reg)
        badchars = ARCHX86._as_bytes(badchars)
        opcodes = []
        shift = 0 if add else 5
        prefix = b"" if adjust else ARCHX86.clear(reg, badchars)

        if bits <= 8 and -0x7F <= value <= 0x7F:
            opcodes.append(prefix + b"\x83" + ARCHX86._byte(ARCHX86.encode_effective(shift, reg)) + ARCHX86._byte(value))

        if bits <= 16 and -0xFFFF <= value <= 0:
            opcodes.append(prefix + b"\x66\x81" + ARCHX86._byte(ARCHX86.encode_effective(shift, reg)) + struct.pack("<H", value & 0xFFFF))

        opcodes.append(prefix + b"\x81" + ARCHX86._byte(ARCHX86.encode_effective(shift, reg)) + ARCHX86.pack_dword(value))
        for opcode in opcodes:
            with contextlib.suppress(RuntimeError):
                return ARCHX86._check_badchars(opcode, badchars)

        if not opcodes:
            raise RuntimeError("Could not find a usable opcode")
        raise RuntimeError("Could not find a usable opcode")

    @staticmethod
    def add(value, reg, badchars=b"", adjust=False, bits=0):
        """Generate an instruction sequence that adds a value to a register."""
        return ARCHX86.sub(value, reg, settings=(badchars, True, adjust, bits))

    @staticmethod
    def pack_word(num):
        """Pack an integer as an unsigned little-endian 16-bit value."""
        return struct.pack("<H", int(num) & 0xFFFF)

    @staticmethod
    def pack_dword(num):
        """Pack an integer as an unsigned little-endian 32-bit value."""
        return struct.pack("<I", int(num) & 0xFFFFFFFF)

    @staticmethod
    def pack_lsb(num):
        """Return the least significant byte of a packed 32-bit value."""
        return ARCHX86.pack_dword(num)[:1]

    @staticmethod
    def adjust_reg(reg, adjustment):
        """Generate instructions that adjust a register by a signed amount."""
        if adjustment > 0:
            return ARCHX86.sub(adjustment, reg, settings=(b"", False, False, 32))
        return ARCHX86.add(adjustment, reg, b"", True, 32)

    @staticmethod
    def fpu_instructions():
        """Return the supported FPU instruction byte sequences."""
        fpus = []
        fpus.extend(b"\xd9" + ARCHX86._byte(value) for value in range(0xE8, 0xEF))
        fpus.extend(b"\xd9" + ARCHX86._byte(value) for value in range(0xC0, 0xD0))
        fpus.extend(b"\xda" + ARCHX86._byte(value) for value in range(0xC0, 0xE0))
        fpus.extend(b"\xdb" + ARCHX86._byte(value) for value in range(0xC0, 0xE0))
        fpus.extend(b"\xdd" + ARCHX86._byte(value) for value in range(0xC0, 0xC8))

        fpus.extend((b"\xd9\xd0", b"\xd9\xe1", b"\xd9\xf6", b"\xd9\xf7", b"\xd9\xe5"))
        # The original implementation notes that DB E1 fails consistently on Linux.
        return fpus

    @staticmethod
    def geteip_fpu(badchars=b"", modified_registers=None):
        """Build an FPU-based GetEIP stub that avoids forbidden bytes."""
        if modified_registers is None:
            modified_registers = []

        badchars = ARCHX86._as_bytes(badchars or b"")

        # Bail out early if D9 is restricted.
        if b"\xd9" in badchars:
            return None

        fpus = ARCHX86.fpu_instructions()
        fpus = [instruction for instruction in fpus if not any(byte in badchars for byte in instruction)]
        if not fpus:
            return None

        dsts = [reg for reg in range(8) if (0x70 + reg) not in badchars]
        if ARCHX86.ESP in dsts and 0x24 in badchars:
            dsts.remove(ARCHX86.ESP)
        if not dsts:
            return None

        fpu = random.choice(fpus)

        while dsts:
            buf = b""
            mod_registers = [ARCHX86.ESP]
            dst = random.choice(dsts)
            dsts.remove(dst)

            # If the register is not ESP, copy ESP into it.
            if dst != ARCHX86.ESP:
                mod_registers.append(dst)
                if 0x70 + dst in badchars:
                    mod_registers.remove(dst)
                    continue

                if 0x89 not in badchars and (0xE0 + dst) not in badchars:
                    buf += b"\x89" + ARCHX86._byte(0xE0 + dst)
                else:
                    if 0x54 in badchars or (0x58 + dst) in badchars:
                        mod_registers.remove(dst)
                        continue
                    buf += b"\x54" + ARCHX86._byte(0x58 + dst)

            pad = 0
            while pad < (128 - 12) and (256 - 12 - pad) % 256 in badchars:
                pad += 4
            if pad == (128 - 12):
                return None

            out = buf + fpu + b"\xd9" + ARCHX86._byte(0x70 + dst)
            if dst == ARCHX86.ESP:
                out += b"\x24"
            out += ARCHX86._byte(256 - 12 - pad)

            regs = list(range(8))
            while regs:
                reg = random.choice(regs)
                regs.remove(reg)

                if reg == ARCHX86.ESP or (0x58 + reg) in badchars:
                    continue

                mod_registers.append(reg)

                # Pop the value back out.
                out += ARCHX86._byte(0x58 + reg) * (pad // 4 + 1)

                # Fix the value to point to itself.
                gap = len(out) - len(buf)

                # Preserve insertion order while removing duplicates.
                for modified in dict.fromkeys(mod_registers):
                    if modified not in modified_registers:
                        modified_registers.append(modified)

                return out, ARCHX86.reg_names32[reg].upper(), gap

            # No suitable pop register was found for this destination.
            if dst in mod_registers:
                mod_registers.remove(dst)

        return None

    @staticmethod
    def register_names_to_ids(value):
        """Parse register names into unique numeric register IDs."""
        if value is None:
            value = ""
        if not isinstance(value, str):
            value = str(value)

        register_ids = []
        for reg in re.split(r"[,\s]", value.strip()):
            reg = reg.strip().upper()

            if reg and reg in ARCHX86._registers:
                register_id = ARCHX86._registers[reg]

                if register_id not in register_ids:
                    register_ids.append(register_id)

        return register_ids
