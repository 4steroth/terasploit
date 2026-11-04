import struct
from collections.abc import Mapping, Sequence

from teralibs.terasploit.framework.console.package import DATASTORE
from teralibs.tsf.base.encoder import ARCH_X86, EncoderRank
from teralibs.tsf.core.encoder.xor_additive_feedback import XorAdditiveFeedback
from teralibs.tsf.pex.poly import EncodingError, LogicalBlock, LogicalRegister, SymbolicBlock


class TerasploitModule(XorAdditiveFeedback):
    """x86 polymorphic XOR additive-feedback encoder."""

    NAME: str = "x86 Shikata Ga Nai"
    DESCRIPTION: str = (
        "This encoder implements a polymorphic XOR additive feedback encoder. "
        "The decoder stub is generated based on dynamic instruction "
        "substitution and dynamic block ordering.  Registers are also "
        "EncoderRankselected dynamically. "
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: int = EncoderRank.EXCELLENT
    REFERENCES: Sequence = [
        [
            "URL",
            "https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x86/shikata_ga_nai.rb",
        ],
    ]
    ARCH: Sequence = [ARCH_X86]
    MAX_ITERATIONS: int = 512

    # Decoder block configuration constants (KeySize and BlockSize) that can be
    # referenced by the block generation methods to maintain consistency across
    # the generated code.
    DECODER: Mapping = {
        "KeyOffset": None,  # Key is embedded via XORK sentinel in the poly stub, not at a fixed offset.
        "KeySize": 4,
        "BlockSize": 4,
    }

    def fpu_instructions(self) -> list[bytes]:
        """
        Generate a comprehensive list of FPU instruction
        byte sequences for use in the decoder stub.
        """
        fpus: list[bytes] = []

        # 0xe8.upto(0xee) -> range(0xe8, 0xef)
        for x in range(0xE8, 0xEF):
            fpus.append(b"\xd9" + bytes([x]))

        # 0xc0.upto(0xcf) -> range(0xc0, 0xd0)
        for x in range(0xC0, 0xD0):
            fpus.append(b"\xd9" + bytes([x]))

        # 0xc0.upto(0xdf) -> range(0xc0, 0xe0)
        for x in range(0xC0, 0xE0):
            fpus.append(b"\xda" + bytes([x]))

        # 0xc0.upto(0xdf) -> range(0xc0, 0xe0)
        for x in range(0xC0, 0xE0):
            fpus.append(b"\xdb" + bytes([x]))

        # 0xc0.upto(0xc7) -> range(0xc0, 0xc8)
        for x in range(0xC0, 0xC8):
            fpus.append(b"\xdd" + bytes([x]))

        # Append static standalone FPU instruction sequences
        fpus.append(b"\xd9\xd0")
        fpus.append(b"\xd9\xe1")
        fpus.append(b"\xd9\xf6")
        fpus.append(b"\xd9\xf7")
        fpus.append(b"\xd9\xe5")

        # This FPU instruction seems to fail consistently on Linux
        # fpus.append(b"\xdb\xe1")

        return fpus

    def sub_immediate(self, regnum: int, imm: int) -> bytes:
        """Generate the appropriate SUB instruction encoding based on the immediate value size."""
        if imm is None or imm == 0:
            return b""

        # Determine if value requires 32-bit (DWORD) or fits in an 8-bit signed byte
        if imm > 255 or imm < -255:
            # \x81 -> SUB r/m32, imm32
            return b"\x81" + bytes([0xE8 + regnum]) + struct.pack("<i", imm)

        # \x83 -> SUB r/m32, imm8
        return b"\x83" + bytes([0xE8 + regnum]) + struct.pack("b", imm)

    def add_immediate(self, regnum: int, imm: int) -> bytes:
        """Generate the appropriate ADD instruction encoding based on the immediate value size."""
        if imm is None or imm == 0:
            return b""

        # Determine if value requires 32-bit (DWORD) or fits in an 8-bit signed byte
        if imm > 255 or imm < -255:
            # \x81 -> ADD r/m32, imm32
            return b"\x81" + bytes([0xC0 + regnum]) + struct.pack("<i", imm)

        # \x83 -> ADD r/m32, imm8
        return b"\x83" + bytes([0xC0 + regnum]) + struct.pack("b", imm)

    def inc(self, regnum: int) -> bytes:
        """INC reg (32-bit mode single-byte opcode)."""
        # INC reg (32-bit mode single-byte opcode)
        return bytes([0x40 + regnum])

    def dec(self, regnum: int) -> bytes:
        """DEC reg (32-bit mode single-byte opcode)."""
        # DEC reg (32-bit mode single-byte opcode)
        return bytes([0x48 + regnum])

    def _xor_op(self, b, addr_reg, key_reg) -> bytes:
        """Generate the XOR instruction encoding for the given address and key registers."""
        return b"\x31" + bytes([0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))])

    def _add_op(self, b, addr_reg, key_reg) -> bytes:
        """Generate the ADD instruction encoding for the given address and key registers."""
        return b"\x03" + bytes([0x40 + b.regnum_of(addr_reg) + (8 * b.regnum_of(key_reg))])

    def _mov_op(self, b, addr_reg, buff_reg) -> bytes:
        """Generate the MOV instruction encoding for the given address and buffer registers."""
        return b"\x89" + bytes([0xC0 + b.regnum_of(addr_reg) + (8 * b.regnum_of(buff_reg))])

    def _init_key_context(self, b, key_reg) -> bytes:
        """Generate the key initialization block using a memory reference to a static value."""
        regnum = b.regnum_of(key_reg)
        modrm = 0x05 | (regnum << 3)
        return b"\x8b" + bytes([modrm]) + b"XORK"

    def _init_key_direct(self, b, key_reg) -> bytes:
        """Generate the key initialization block using a direct immediate value."""
        return bytes([0xB8 + b.regnum_of(key_reg)]) + b"XORK"

    def _lea_perm(self, b, addr_reg, buff_reg, offset: int) -> bytes:
        """Generate a LEA instruction encoding with the specified offset."""
        addr_num = b.regnum_of(addr_reg)
        buff_num = b.regnum_of(buff_reg)

        if offset < -255 or offset > 255:
            return b"\x8d" + bytes([0x80 + buff_num + (8 * addr_num)]) + struct.pack("<i", offset)

        if offset != 0:
            return b"\x8d" + bytes([0x40 + buff_num + (8 * addr_num)]) + struct.pack("b", offset)

        return b"\x8d" + bytes([buff_num + (8 * addr_num)])

    def generate_shikata_block(self, state, length: int, cutoff: int) -> bytes:
        """Generates a polymorphic XOR additive feedback block of the specified length."""

        # Reset the thread-local block registry so every LogicalBlock("name") call
        # within this encoding attempt resolves to the same object.
        LogicalBlock.reset_registry()

        count = LogicalRegister("count", "ecx")
        addr = LogicalRegister("addr")

        key = LogicalRegister("key", "eax") if state.context_encoding else LogicalRegister("key")

        endb = SymbolicBlock.END
        clear_register = LogicalBlock("clear_register", b"\x31\xc9", b"\x29\xc9", b"\x33\xc9", b"\x2b\xc9")

        self._clear_counter_layout_config(length)
        self._dynamic_key_setup_block_selection(state, key)

        math_algorithm = self._handle_specific_configuration(state, endb, key, cutoff)
        self._build_block_iteration_groupings(math_algorithm)

        # 6. Apply Execution Node Rules
        clear_register.depends_on(LogicalBlock("getpc"))
        LogicalBlock("init_counter").depends_on(clear_register)

        LogicalBlock("loop_block").depends_on(LogicalBlock("init_counter"), LogicalBlock("init_key"))
        LogicalBlock("loop_inst").depends_on(LogicalBlock("loop_block"))

        # 7. Package Compilation Pipeline Execution
        try:
            active_registers = [count, addr, key]
            if DATASTORE.get("BufferRegister") and LogicalBlock("buff") is not None:
                active_registers.append(LogicalRegister("buff", DATASTORE.get("BufferRegister")))

            return LogicalBlock("loop_inst").generate(self.block_generator_register_blacklist(), active_registers, state.badchars)

        except (RuntimeError, Exception) as exc:
            raise EncodingError from exc

    def _clear_counter_layout_config(self, length):
        """Step 2 - Generate Shikata Block."""

        init_counter = LogicalBlock("init_counter")

        # Add 4 bytes for the key DWORD, then pad to the next 4-byte boundary.
        # Parentheses are mandatory: without them Python evaluates
        #   4 + (4 - (length & 3)) & 3
        # as
        #   4 + ((4 - (length & 3)) & 3)
        # which adds the wrong pad amount for non-aligned lengths.
        length = (length + 4 + 3) & ~3
        length //= 4

        if length <= 255:
            init_counter.add_perm(b"\xb1" + struct.pack("B", length))
            return init_counter

        if length <= 65536:
            init_counter.add_perm(b"\x66\xb9" + struct.pack("<H", length))
            return init_counter

        init_counter.add_perm(b"\xb9" + struct.pack("<I", length))
        return init_counter

    def _dynamic_key_setup_block_selection(self, state, key):
        """Step 3 - Generate Shikata Block."""

        if state.context_encoding:

            def key_ctx_callback(b):
                """Generate the key initialization block using a memory reference to a static value."""
                return self._init_key_context(b, key)

            LogicalBlock("init_key", key_ctx_callback)

        else:

            def key_dir_callback(b):
                """Generate the key initialization block using a direct immediate value."""
                return self._init_key_direct(b, key)

            LogicalBlock("init_key", key_dir_callback)

    def _handle_getpc_no_buff(self, endb, key, cutoff):
        """Handles getpc logical block if no set buffer register in datastore."""

        # FPU Baseline Execution Blocks
        fpu = LogicalBlock("fpu", *self.fpu_instructions())
        fnstenv = LogicalBlock("fnstenv", b"\xd9\x74\x24\xf4")
        fnstenv.depends_on(fpu)

        def getpc_fpu_callback(b):
            """
            Generate the GETPC block variant that calculates the payload
            address using the FPU-based method.
            """
            return bytes([0x58 + b.regnum_of(LogicalRegister("addr"))])

        getpc = LogicalBlock("getpc", getpc_fpu_callback)
        getpc.depends_on(fnstenv)

        # Dynamic Math Offsets (FPU Config)
        def xor1(b):
            """
            Generate an XOR operation block variant that calculates the offset.
            """
            return self._xor_op(b, LogicalRegister("addr"), key) + struct.pack("b", b.offset_of(endb) - b.offset_of(fpu) - cutoff)

        def xor2(b):
            """
            Generate an XOR operation block variant that calculates the offset.
            """
            return self._xor_op(b, LogicalRegister("addr"), key) + struct.pack("b", b.offset_of(endb) - b.offset_of(fpu) - 4 - cutoff)

        def add1(b):
            """
            Generate an ADD operation block variant that calculates the offset.
            """
            return self._add_op(b, LogicalRegister("addr"), key) + struct.pack("b", b.offset_of(endb) - b.offset_of(fpu) - cutoff)

        def add2(b):
            """
            Generate an ADD operation block variant that calculates the offset.
            """
            return self._add_op(b, LogicalRegister("addr"), key) + struct.pack("b", b.offset_of(endb) - b.offset_of(fpu) - 4 - cutoff)

        return (xor1, xor2, add1, add2)

    def _handle_getpc(self, endb, cutoff, key):
        """Handles getpc logical block."""

        offset = int(DATASTORE.get("BufferOffset") or 0)

        def getpc_add_offset(b):
            """
            Generate a GETPC block variant that calculates the payload address
            using an ADD instruction with the specified offset.
            """
            return self._mov_op(b, LogicalBlock("addr"), LogicalBlock("buff")) + self.add_immediate(b.regnum_of(LogicalBlock("addr")), offset)

        def getpc_sub_offset(b):
            """
            Generate a GETPC block variant that calculates the payload address
            using a SUB instruction with the specified offset.
            """
            return self._mov_op(b, LogicalBlock("addr"), LogicalBlock("buff")) + self.sub_immediate(b.regnum_of(LogicalBlock("addr")), -offset)

        LogicalBlock("getpc").add_perm(getpc_add_offset, getpc_sub_offset)

        if 0 < offset < 4:

            def getpc_inc_offset(b):
                """
                Generate a GETPC block variant that calculates the payload address
                using an INC instruction with the specified offset.
                """
                return self._mov_op(b, LogicalBlock("addr"), LogicalBlock("buff")) + self.inc(b.regnum_of(LogicalBlock("addr"))) * offset

            LogicalBlock("getpc").add_perm(getpc_inc_offset)

        elif -4 < offset < 0:

            def getpc_dec_offset(b):
                """
                Generate a GETPC block variant that calculates the payload address
                using a DEC instruction with the specified offset.
                """
                return self._mov_op(b, LogicalBlock("addr"), LogicalBlock("buff")) + self.dec(b.regnum_of(LogicalBlock("addr"))) * -offset

            LogicalBlock("getpc").add_perm(getpc_dec_offset)

        def getpc_lea_perm(b):
            """
            Generate a GETPC block variant that calculates the payload address
            using a LEA instruction with the specified offset.
            """
            return self._lea_perm(b, LogicalBlock("addr"), LogicalBlock("buff"), offset)

        LogicalBlock("getpc").add_perm(getpc_lea_perm)

        # Dynamic Math Offsets (Buffer Config)
        def xor1(b):
            """
            Generate an XOR operation block variant that calculates the offset.
            """
            return self._xor_op(b, LogicalBlock("addr"), key) + struct.pack("b", b.offset_of(endb) - cutoff)

        def xor2(b):
            """
            Generate an XOR operation block variant that calculates the offset.
            """
            return self._xor_op(b, LogicalBlock("addr"), key) + struct.pack("b", b.offset_of(endb) - 4 - cutoff)

        def add1(b):
            """
            Generate an ADD operation block variant that calculates the offset.
            """
            return self._add_op(b, LogicalBlock("addr"), key) + struct.pack("b", b.offset_of(endb) - cutoff)

        def add2(b):
            """
            Generate an ADD operation block variant that calculates the offset.
            """
            return self._add_op(b, LogicalBlock("addr"), key) + struct.pack("b", b.offset_of(endb) - 4 - cutoff)

        return (xor1, xor2, add1, add2)

    def _handle_specific_configuration(self, state, endb, key, cutoff):
        """Step 4 - Generate Shikata Block."""

        if DATASTORE.get("BufferRegister") is None:
            return self._handle_getpc_no_buff(endb, key, cutoff)

        LogicalRegister("buff", DATASTORE.get("BufferRegister"))
        offset = int(DATASTORE.get("BufferOffset") or 0)

        if (offset < -255 or offset > 255) and b"\x00" in state.badchars:
            raise EncodingError("Can't generate NULL-free decoder with a BufferOffset bigger than one byte")

        return self._handle_getpc(endb, cutoff, key)

    def _build_block_iteration_groupings(self, math_algorithm):
        """Step 5 - Generate Shikata Block."""

        xor1, xor2, add1, add2 = math_algorithm

        # 5. Build Block Iteration Groupings
        def sub4(b):
            """
            Generate a SUB operation block variant that subtracts 4 from the specified register.
            """
            return self.sub_immediate(b.regnum_of(LogicalBlock("addr")), -4)

        def add4(b):
            """
            Generate an ADD operation block variant that adds 4 to the specified register.
            """
            return self.add_immediate(b.regnum_of(LogicalBlock("addr")), 4)

        def perm_1(b):
            """Calculate the offset to the end of the payload."""
            return xor1(b) + add1(b) + sub4(b)

        def perm_2(b):
            """Calculate the offset to the end of the payload."""
            return xor1(b) + sub4(b) + add2(b)

        def perm_3(b):
            """Calculate the offset to the end of the payload."""
            return sub4(b) + xor2(b) + add2(b)

        def perm_4(b):
            """Calculate the offset to the end of the payload."""
            return xor1(b) + add1(b) + add4(b)

        def perm_5(b):
            """Calculate the offset to the end of the payload."""
            return xor1(b) + add4(b) + add2(b)

        def perm_6(b):
            """Calculate the offset to the end of the payload."""
            return add4(b) + xor2(b) + add2(b)

        LogicalBlock("loop_block").add_perm(perm_1, perm_2, perm_3, perm_4, perm_5, perm_6)
        LogicalBlock("loop_inst", b"\xe2\xf5")

    def block_generator_register_blacklist(self) -> list[int]:
        """
        Determine the set of registers to blacklist during block generation.
        """
        # 1. Define standard x86 register ID indexes matching your engine mapping
        # 'ecx' = 1, 'esp' = 4
        ecx_idx = 1
        esp_idx = 4

        # 2. Extract user or framework defined saved registers list
        # (Defaults to empty list if not defined on your class instance)
        saved = getattr(self, "saved_registers", [])

        # 3. Perform a Set Union operation to merge and deduplicate lists
        # This prevents duplicate constraints while blacklisting ESP and ECX
        blacklist_set = {esp_idx, ecx_idx}.union(saved)

        return list(blacklist_set)

    def decoder_stub(self, state) -> bytes:
        """
        Generate and return the polymorphic XOR additive-feedback decoder stub.
        """

        stub = self.generate_shikata_block(state, len(state.buf), 0)

        # Replace the XORK sentinel embedded by _init_key_direct / _init_key_context
        # with the actual starting key packed as a little-endian DWORD.
        packed_key = struct.pack("<I", state.key & 0xFFFFFFFF)
        stub = stub.replace(b"XORK", packed_key)

        return stub

    def can_avoid(self, bad_bytes):
        """
        Return False when any constant stub byte is forbidden.
        """
        return True
