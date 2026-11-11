import struct
from collections import namedtuple
from collections.abc import Mapping, Sequence

from teralibs.tsf.base.encoder import ARCH_X86, EncoderError, EncoderRank
from teralibs.tsf.core.encoder.xor_additive_feedback import XorAdditiveFeedback
from teralibs.tsf.pex.architecture.x86 import ARCHX86
from teralibs.tsf.pex.poly import EncodingError, LogicalBlock, LogicalRegisterX86, SymbolicBlock


# Groups the three register references that every block-building helper needs,
# avoiding wide argument lists across the private helpers below.
PolymorphicRegs = namedtuple("PolymorphicRegs", ["addr", "key", "endb"])


class TerasploitModule(XorAdditiveFeedback):
    """x86 polymorphic XOR additive-feedback encoder."""

    NAME: str = "x86 Polymorphic XOR Additive Feedback"
    DESCRIPTION: str = (
        "This encoder implements a polymorphic XOR additive feedback encoder. "
        "The decoder stub is generated based on dynamic instruction "
        "substitution and dynamic block ordering. Registers are also "
        "EncoderRankselected dynamically. "
    )
    AUTHOR: Sequence = ["spoonm - original msf", "4steroth - terasploit implementation"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: int = EncoderRank.EXCELLENT
    REFERENCES: Sequence = [
        ["URL", "https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x86/shikata_ga_nai.rb"],
    ]
    ARCH: Sequence = [ARCH_X86]
    MAX_ITERATIONS: int = 512

    # KeySize and BlockSize are referenced across block generation methods
    # to keep encoding parameters consistent throughout the generated stub.
    DECODER: Mapping = {
        "KeyOffset": None,  # Key is embedded via XORK sentinel; no fixed offset.
        "KeySize": 4,
        "BlockSize": 4,
    }

    @staticmethod
    def _pack_byte(value) -> bytes:
        """Pack a single byte."""
        return bytes([value & 0xFF])

    @staticmethod
    def _pack_dword(value) -> bytes:
        """Pack a little-endian unsigned 32-bit integer."""
        return struct.pack("<I", value & 0xFFFFFFFF)

    def _xor_inst(self, b, regs: PolymorphicRegs) -> bytes:
        """XOR r/m32, r32 ModRM encoding for the addr and key registers."""
        return b"\x31" + self._pack_byte(0x40 + b.regnum_of(regs.addr) + (8 * b.regnum_of(regs.key)))

    def _add_inst(self, b, regs: PolymorphicRegs) -> bytes:
        """ADD r32, r/m32 ModRM encoding for the addr and key registers."""
        return b"\x03" + self._pack_byte(0x40 + b.regnum_of(regs.addr) + (8 * b.regnum_of(regs.key)))

    def _build_init_counter(self, length) -> LogicalBlock:
        """Build the init_counter block for the aligned DWORD count of length."""
        init_counter = LogicalBlock("init_counter")

        # Align to the next 4-byte boundary and convert to DWORD count.
        length += 4 + ((4 - (length & 3)) & 3)
        length //= 4

        if length <= 255:
            init_counter.add_perm(b"\xb1" + self._pack_byte(length))
        elif length <= 65536:
            init_counter.add_perm(b"\x66\xb9" + struct.pack("<H", length & 0xFFFF))
        else:
            init_counter.add_perm(b"\xb9" + self._pack_dword(length))

        return init_counter

    def _build_init_key(self, state, regs: PolymorphicRegs) -> LogicalBlock:
        """Build the init_key block for context or direct key encoding."""
        opcode = 0xA1 if state.context_encoding else 0xB8
        return LogicalBlock(
            "init_key",
            lambda b: self._pack_byte(opcode + b.regnum_of(regs.key)) + b"XORK",
        )

    def _build_buffer_getpc(self, state, regs: PolymorphicRegs) -> LogicalBlock:
        """Build the getpc block using the configured BufferRegister."""
        buff_reg = LogicalRegisterX86("buff", self.DATASTORE["BufferRegister"])
        offset = int(self.DATASTORE["BufferOffset"]) if self.DATASTORE["BufferOffset"] else 0

        if (offset < -255 or offset > 255) and state.badchars and 0 in state.badchars:
            raise EncodingError("Can't generate NULL-free decoder with a BufferOffset bigger than one byte")

        def mov(b):
            """MOV r/m32, r32 from addr to buff register."""
            return b"\x89" + self._pack_byte(0xC0 + b.regnum_of(regs.addr) + (8 * b.regnum_of(buff_reg)))

        def add_offset(b):
            """ADD the configured buffer offset to the addr register."""
            return self.add_immediate(b.regnum_of(regs.addr), offset)

        def sub_offset(b):
            """SUB the negated buffer offset from the addr register."""
            return self.sub_immediate(b.regnum_of(regs.addr), -offset)

        def lea(b):
            """LEA addr_reg, [buff_reg+offset] in the appropriate displacement form."""
            if offset < -255 or offset > 255:
                return b"\x8d" + self._pack_byte(0x80 + b.regnum_of(buff_reg) + (8 * b.regnum_of(regs.addr))) + self._pack_dword(offset)
            if -255 < offset < 255 and offset != 0:
                return b"\x8d" + self._pack_byte(0x40 + b.regnum_of(buff_reg) + (8 * b.regnum_of(regs.addr))) + self._pack_byte(offset)
            return b"\x8d" + self._pack_byte(b.regnum_of(buff_reg) + (8 * b.regnum_of(regs.addr)))

        getpc = LogicalBlock("getpc")
        getpc.add_perm(lambda b: mov(b) + add_offset(b))
        getpc.add_perm(lambda b: mov(b) + sub_offset(b))

        if 0 < offset < 4:
            getpc.add_perm(lambda b: mov(b) + self.inc(b.regnum_of(regs.addr)) * offset)
        elif -4 < offset < 0:
            getpc.add_perm(lambda b: mov(b) + self.dec(b.regnum_of(regs.addr)) * -offset)

        getpc.add_perm(lea)
        return getpc

    def _build_buffer_math_ops(self, regs: PolymorphicRegs, cutoff) -> tuple:
        """Return the four math offset ops for BufferRegister addressing mode."""

        def xor1(b):
            """XOR [addr+disp8], key — disp relative to end block."""
            return self._xor_inst(b, regs) + self._pack_byte(b.offset_of(regs.endb) - cutoff)

        def xor2(b):
            """XOR variant with disp adjusted by -4."""
            return self._xor_inst(b, regs) + self._pack_byte(b.offset_of(regs.endb) - 4 - cutoff)

        def add1(b):
            """ADD key, [addr+disp8] — disp relative to end block."""
            return self._add_inst(b, regs) + self._pack_byte(b.offset_of(regs.endb) - cutoff)

        def add2(b):
            """ADD variant with disp adjusted by -4."""
            return self._add_inst(b, regs) + self._pack_byte(b.offset_of(regs.endb) - 4 - cutoff)

        return xor1, xor2, add1, add2

    def _build_fpu_getpc(self, regs: PolymorphicRegs) -> tuple:
        """Build the FPU-based getpc block; returns (getpc, fpu)."""
        fpu = LogicalBlock("fpu", *self.fpu_instructions())
        fnstenv = LogicalBlock("fnstenv", b"\xd9\x74\x24\xf4")
        fnstenv.depends_on(fpu)

        getpc = LogicalBlock("getpc", lambda b: self._pack_byte(0x58 + b.regnum_of(regs.addr)))
        getpc.depends_on(fnstenv)
        return getpc, fpu

    def _build_fpu_math_ops(self, regs: PolymorphicRegs, cutoff, fpu) -> tuple:
        """Return the four math offset ops for FPU addressing mode."""

        def xor1(b):
            """XOR [addr+disp8], key — disp relative to fpu block."""
            return self._xor_inst(b, regs) + self._pack_byte(b.offset_of(regs.endb) - b.offset_of(fpu) - cutoff)

        def xor2(b):
            """XOR variant with disp adjusted by -4."""
            return self._xor_inst(b, regs) + self._pack_byte(b.offset_of(regs.endb) - b.offset_of(fpu) - 4 - cutoff)

        def add1(b):
            """ADD key, [addr+disp8] — disp relative to fpu block."""
            return self._add_inst(b, regs) + self._pack_byte(b.offset_of(regs.endb) - b.offset_of(fpu) - cutoff)

        def add2(b):
            """ADD variant with disp adjusted by -4."""
            return self._add_inst(b, regs) + self._pack_byte(b.offset_of(regs.endb) - b.offset_of(fpu) - 4 - cutoff)

        return xor1, xor2, add1, add2

    def _build_getpc_and_math(self, state, regs: PolymorphicRegs, cutoff) -> tuple:
        """Select addressing mode and return (getpc, math_ops)."""
        if self.DATASTORE["BufferRegister"]:
            getpc = self._build_buffer_getpc(state, regs)
            math_ops = self._build_buffer_math_ops(regs, cutoff)
            return getpc, math_ops

        getpc, fpu = self._build_fpu_getpc(regs)
        math_ops = self._build_fpu_math_ops(regs, cutoff, fpu)
        return getpc, math_ops

    def _assemble_loop(self, regs: PolymorphicRegs, math_ops) -> tuple:
        """Build loop_block permutations and loop_inst from math_ops."""
        xor1, xor2, add1, add2 = math_ops

        def sub4(b):
            """SUB 4 from the addr register."""
            return self.sub_immediate(b.regnum_of(regs.addr), -4)

        def add4(b):
            """ADD 4 to the addr register."""
            return self.add_immediate(b.regnum_of(regs.addr), 4)

        loop_block = LogicalBlock("loop_block")
        loop_block.add_perm(
            lambda b: xor1(b) + add1(b) + sub4(b),
            lambda b: xor1(b) + sub4(b) + add2(b),
            lambda b: sub4(b) + xor2(b) + add2(b),
            lambda b: xor1(b) + add1(b) + add4(b),
            lambda b: xor1(b) + add4(b) + add2(b),
            lambda b: add4(b) + xor2(b) + add2(b),
        )

        loop_inst = LogicalBlock("loop_inst", b"\xe2\xf5")
        return loop_block, loop_inst

    def generate_polymorphic_block(self, state, length, cutoff):
        """Generate a polymorphic decoder block."""
        _count_reg = LogicalRegisterX86("count", "ecx")
        regs = PolymorphicRegs(
            addr=LogicalRegisterX86("addr"),
            key=LogicalRegisterX86("key", "eax") if state.context_encoding else LogicalRegisterX86("key"),
            endb=SymbolicBlock.End(),
        )

        clear_register = LogicalBlock("clear_register", b"\x31\xc9", b"\x29\xc9", b"\x33\xc9", b"\x2b\xc9")
        init_counter = self._build_init_counter(length)
        init_key = self._build_init_key(state, regs)

        getpc, math_ops = self._build_getpc_and_math(state, regs, cutoff)
        loop_block, loop_inst = self._assemble_loop(regs, math_ops)

        clear_register.depends_on(getpc)
        init_counter.depends_on(clear_register)
        loop_block.depends_on(init_counter, init_key)
        loop_inst.depends_on(loop_block)

        try:
            return loop_inst.generate(self.block_generator_register_blacklist(), None, state.badchars)
        except (RuntimeError, EncodingError) as exc:
            raise EncodingError(str(exc)) from exc

    def decoder_stub(self, state):
        """Generate and cache the polymorphic decoder stub for the given state."""
        if state.decoder_stub is not None:
            return state.decoder_stub

        if set(self.modified_registers()) & set(self.saved_registers()):
            raise EncoderError("Saved registers overlap with registers modified by the encoder.")

        cutoff = 4 - (len(state.buf) & 3)
        block = self.generate_polymorphic_block(state, len(state.buf) + cutoff, cutoff)

        if block is None:
            raise EncoderError("Failed to generate the polymorphic xor additive feedback decoder stub.")

        state.decoder_key_offset = block.index(b"XORK")
        state.buf = block[-cutoff:] + state.buf
        state.decoder_stub = block[:-cutoff]

        return state.decoder_stub

    def fpu_instructions(self):
        """Return FPU instruction byte sequences for the decoder stub."""
        fpus = []
        for x in range(0xE8, 0xEF):
            fpus.append(b"\xd9" + bytes([x]))
        for x in range(0xC0, 0xD0):
            fpus.append(b"\xd9" + bytes([x]))
        for x in range(0xC0, 0xE0):
            fpus.append(b"\xda" + bytes([x]))
        for x in range(0xC0, 0xE0):
            fpus.append(b"\xdb" + bytes([x]))
        for x in range(0xC0, 0xC8):
            fpus.append(b"\xdd" + bytes([x]))
        fpus.extend([b"\xd9\xd0", b"\xd9\xe1", b"\xd9\xf6", b"\xd9\xf7", b"\xd9\xe5"])
        return fpus

    def can_preserve_registers(self):
        """Indicate that this encoder supports register preservation."""
        return True

    def modified_registers(self):
        """Return registers always modified by this encoder."""
        return [ARCHX86.ECX, ARCHX86.EAX, ARCHX86.EDX]

    def block_generator_register_blacklist(self):
        """Return registers excluded from dynamic selection during block generation."""
        saved = self.saved_registers() or []
        return list(dict.fromkeys([ARCHX86.ESP, ARCHX86.ECX, *saved]))

    def saved_registers(self):
        """Convert SaveRegisters datastore value into x86 register constants."""
        return ARCHX86.register_names_to_ids(self.DATASTORE["SaveRegisters"])

    def sub_immediate(self, regnum, imm):
        """Generate machine code to subtract an immediate value from a register."""
        if imm is None or imm == 0:
            return b""
        if imm > 255 or imm < -255:
            return b"\x81" + bytes([0xE8 + regnum]) + struct.pack("<I", imm & 0xFFFFFFFF)
        return b"\x83" + bytes([0xE8 + regnum]) + bytes([imm & 0xFF])

    def add_immediate(self, regnum, imm):
        """Generate machine code to add an immediate value to a register."""
        if imm is None or imm == 0:
            return b""
        if imm > 255 or imm < -255:
            return b"\x81" + bytes([0xC0 + regnum]) + struct.pack("<I", imm & 0xFFFFFFFF)
        return b"\x83" + bytes([0xC0 + regnum]) + bytes([imm & 0xFF])

    def inc(self, regnum):
        """INC reg (32-bit single-byte opcode)."""
        return bytes([0x40 + regnum])

    def dec(self, regnum):
        """DEC reg (32-bit single-byte opcode)."""
        return bytes([0x48 + regnum])
