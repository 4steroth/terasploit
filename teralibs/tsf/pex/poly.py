import random
from collections.abc import Mapping

from teralibs.tsf.pex.text import Text


class EncodingError(Exception):
    """Raised when the mutation engine cannot satisfy conditions without hit bad bytes."""


class InvalidRegisterError(Exception):
    """Raised if the register has not been assigned."""

    def __init__(self, reg):
        self.reg = reg
        super().__init__(f"Register has not been assigned: {reg.name}")


class LogicalRegister:
    """Poly logical register."""

    def __init__(self, name, regnum=None):
        self._name = name
        self._regnum = regnum
        self._static = regnum is not None

    @classmethod
    def regnum_set(cls):
        """`ragnum_set` only exists in x86 architecture."""
        raise NotImplementedError

    @property
    def name(self):
        """Return name."""
        return self._name

    @property
    def regnum(self):
        """Return register number."""
        if self._regnum is None:
            raise InvalidRegisterError(self)

        return self._regnum

    @regnum.setter
    def regnum(self, value):
        if self.static():
            raise RuntimeError("Attempted to assign regnum to static register")

        self._regnum = value

    def static(self):
        """Return static value."""
        return self._static

    def __repr__(self):
        return f"{self.__class__.__name__}(name={self.name!r}, regnum={self._regnum!r}, static={self._static})"


class LogicalRegisterX86(LogicalRegister):
    """Logical register for architecture x86"""

    EAX = 0
    ECX = 1
    EDX = 2
    EBX = 3
    ESP = 4
    EBP = 5
    ESI = 6
    EDI = 7

    REGISTERS: Mapping = {"eax": EAX, "ecx": ECX, "edx": EDX, "ebx": EBX, "esp": ESP, "ebp": EBP, "esi": ESI, "edi": EDI}

    @classmethod
    def regnum_set(cls):
        return [cls.EAX, cls.EBX, cls.ECX, cls.EDX, cls.ESI, cls.EDI, cls.EBP, cls.ESP]

    @classmethod
    def reg_number(cls, register):
        """Return specified register numbder."""
        if isinstance(register, int):
            if register not in cls.REGISTERS.values():
                raise ValueError(f"Invalid x86 register number: {register}")
            return register

        if isinstance(register, str):
            register = register.lower()

            if register in cls.REGISTERS:
                return cls.REGISTERS[register]

        raise ValueError(f"Unknown x86 register: {register}")

    def __init__(self, name, register=None):
        regnum = self.reg_number(register) if register is not None else None

        super().__init__(name, regnum)


class Permutation:
    """Represents a binary permutation associated with a logical block."""

    def __init__(self, perm, block):
        """Initialize the permutation and its associated block."""
        self._perm = perm
        self.block = block

    @property
    def perm(self):
        """Return the underlying permutation."""
        return self._perm

    def to_bytes(self):
        """Generate and return the permutation as bytes."""
        result = self._perm(self.block) if callable(self._perm) else self._perm

        if not isinstance(result, bytes):
            raise TypeError(f"Permutation must produce bytes, got {type(result).__name__}")

        return result

    @property
    def length(self):
        """Return the length of the generated permutation."""
        return len(self.to_bytes())

    def __str__(self):
        """Return a readable representation of the permutation."""
        return repr(self._perm)


class State:
    """Manage the state of polymorphic code generation."""

    def __init__(self):
        """Initialize the polymorphic generation state."""
        self._block_list = None
        self.reset()

    def reset(self):
        """Reset consumed registers, buffer, block list, and generation state."""
        # Reset the generation flag on any blocks in the block list.
        if self._block_list:
            for block in self._block_list:
                block[0].generated = False

        self._regnums = {}
        self._buffer = b""
        self._block_list = []
        self._curr_offset = 0
        self._first_phase = True
        self._badchars = None

    def consumed_regnum(self, regnum):
        """Return whether the supplied register number is already consumed."""
        return self._regnums.get(regnum)

    def consume_regnum(self, regnum):
        """Consume and return a register number."""
        if self.consumed_regnum(regnum):
            raise RuntimeError(f"Register {regnum} is already consumed.")

        self._regnums[regnum] = True

        return regnum

    def consume_regnum_from_set(self, regnum_set):
        """Randomly select and consume an available register number."""
        # Pick a random starting point within the supplied set.
        idx = random.randrange(len(regnum_set))

        # Try each index in the set.
        for x in range(len(regnum_set)):
            regnum = regnum_set[(idx + x) % len(regnum_set)]

            if self.consumed_regnum(regnum):
                continue

            return self.consume_regnum(regnum)

        # No available registers were found.
        raise RuntimeError("No registers are available to consume from the set")

    def defecate_regnum(self, regnum):
        """Release a consumed register number for future use."""
        self._regnums.pop(regnum, None)

    @property
    def buffer(self):
        """Return the current polymorphic generation buffer."""
        return self._buffer

    @buffer.setter
    def buffer(self, value):
        """Set the current polymorphic generation buffer."""
        self._buffer = value

    @property
    def block_list(self):
        """Return the linear list of generated blocks."""
        return self._block_list

    @block_list.setter
    def block_list(self, value):
        """Set the linear list of generated blocks."""
        self._block_list = value

    @property
    def curr_offset(self):
        """Return the current offset into the polymorphic buffer."""
        return self._curr_offset

    @curr_offset.setter
    def curr_offset(self, value):
        """Set the current offset into the polymorphic buffer."""
        self._curr_offset = value

    @property
    def first_phase(self):
        """Return whether generation is in its first phase."""
        return self._first_phase

    @first_phase.setter
    def first_phase(self, value):
        """Set the generation phase flag."""
        self._first_phase = value

    @property
    def badchars(self):
        """Return the characters to avoid during permutation selection."""
        return self._badchars

    @badchars.setter
    def badchars(self, value):
        """Set the characters to avoid during permutation selection."""
        self._badchars = value


class LogicalBlock:
    """Represents a logical block used in polymorphic buffer generation."""

    def __init__(self, name, *perms):
        """Initialize the logical block with a name and optional permutations."""
        self._name = name
        self.perms = []
        self.depends = []
        self.next_blocks_list = []
        self.clobbered_registers = []
        self._offset = None
        self.state = None
        self._once = False
        self.references = 0
        self.used_references = 0
        self._generated = False
        self.reset()
        self.add_perm(*perms)

    def reset(self):
        """Reset the block to its initial state."""
        self.perms = []
        self.depends = []
        self.next_blocks_list = []
        self.clobbered_registers = []
        self._offset = None
        self.state = None
        self._once = False
        self.references = 0
        self.used_references = 0
        self._generated = False

    @property
    def name(self):
        """Return the block's name."""
        return self._name

    @property
    def once(self):
        """Return whether this block should only be generated once."""
        return self._once

    @once.setter
    def once(self, tf):
        """Set whether this block should only be generated once."""
        self._once = tf

    def ref(self):
        """Increment the number of blocks depending on this block."""
        self.references += 1

    def deref(self):
        """Increment the number of completed dependency passes."""
        self.used_references += 1

    def last_reference(self):
        """Return whether no outstanding references remain."""
        return self.references - self.used_references <= 0

    def add_perm(self, *perms):
        """Add one or more permutations to the block."""
        self.perms.extend(perms)

    def rand_perm(self):
        """Return a randomly selected permutation."""
        perm = None
        if self.state:
            perm = self.rand_perm_badchars() if self.state.badchars else Permutation(random.choice(self.perms), self)

        if perm is None:
            raise RuntimeError("Failed to locate a valid permutation.")

        return perm

    def rand_perm_badchars(self):
        """Return a random permutation that does not contain bad characters."""
        idx = random.randrange(len(self.perms))
        off = 0

        while off < len(self.perms):
            p = self.perms[(idx + off) % len(self.perms)]

            if callable(p):
                return Permutation(p, self)

            if self.state is None or self.state.badchars is None:
                return Permutation(p, self)

            if not isinstance(p, bytes):
                raise TypeError(f"Static permutation must be bytes, got {type(p).__name__}")

            if Text.badchar_index(p, self.state.badchars) is None:
                return Permutation(p, self)

            off += 1

        return None

    def depends_on(self, *depends):
        """Set the blocks this block depends on."""
        self.depends = list(depends)

        for block in self.depends:
            block.ref()

    def next_blocks(self, *blocks):
        """Set the blocks that follow this block."""
        self.next_blocks_list = list(blocks)

    def clobbers(self, *registers):
        """Set the logical registers clobbered by this block."""
        self.clobbered_registers = list(registers)

    def each_clobbers(self):
        """Yield each register clobbered by this block."""
        yield from self.clobbered_registers

    def generate(self, save_registers=None, state=None, badchars=None):
        """Generate the polymorphic buffer for this block and its dependencies."""
        # Create a localized state instance if one was not supplied.
        if state is None:
            state = State()

        buf = None
        cnt = 0

        # Try generating at most 128 times until no bad characters are found.
        # Bad characters can be introduced through block offsetting and
        # register number selection, which cannot be readily predicted
        # during the generation phase.
        while True:
            buf = self.do_generate(save_registers, state, badchars)

            if buf and (badchars is None or Text.badchar_index(buf, badchars) is None):
                break

            cnt += 1

            if cnt >= 128:
                break

        # If we passed 128 tries, generation has failed.
        if cnt >= 128:
            buf = None

        return buf

    def offset_of(self, lblock):
        """Return the offset of a logical block."""
        if self.state and self.state.first_phase:
            return 0

        if self.state and isinstance(lblock, SymbolicBlock.End):
            return self.state.curr_offset

        return lblock.offset

    def regnum_of(self, reg):
        """Return the assigned register number of a logical register."""
        if self.state and self.state.first_phase:
            return 0

        return reg.regnum

    def size_of(self, lblock):
        """Return the generated permutation size of a logical block."""
        if self.state:
            for block, perm in self.state.block_list:
                if block is lblock:
                    return perm.length

        return 0

    @property
    def offset(self):
        """Return the block's assigned offset."""
        return self._offset

    @offset.setter
    def offset(self, value):
        """Set the block's assigned offset."""
        self._offset = value

    @property
    def generated(self):
        """Return whether this block has been generated."""
        return self._generated

    @generated.setter
    def generated(self, value):
        """Set whether this block has been generated."""
        self._generated = value

    def do_generate(self, save_registers, state, badchars):
        """Generate the polymorphic buffer by processing dependent blocks."""
        # Reset the state in case it was passed in.
        state.reset()

        # Set the bad character list.
        if badchars:
            state.badchars = badchars

        # Consume any registers that should be saved.
        if save_registers:
            for reg in save_registers:
                state.consume_regnum(reg)

        # Build the linear list of blocks that will be processed.
        # Each element is a two-member list:
        # [LogicalBlock instance, associated Permutation instance].
        block_list = self.generate_block_list(state)

        # Transition into the second phase, enabling offset_of and regnum_of
        # calls to return real values.
        state.first_phase = False

        # Generate the buffer block by block, assigning registers as necessary.
        if block_list:
            for b in block_list:
                # Generate the next permutation and append it to the buffer.
                while True:
                    try:
                        state.buffer += b[1].to_bytes()
                        break

                    # If an invalid register exception is raised, consume a random
                    # register from the associated architecture register number set.
                    except InvalidRegisterError as e:
                        e.reg.regnum = state.consume_regnum_from_set(e.reg.__class__.regnum_set())

                # Release registers clobbered by this block.
                def process_clobbered_register(reg):
                    """Release a clobbered register and clear its register number."""
                    try:
                        state.defecate_regnum(reg.regnum)
                        reg.regnum = None
                    except InvalidRegisterError:
                        pass

                for reg in b[0].each_clobbers():
                    process_clobbered_register(reg)

        # Return the generated buffer.
        return state.buffer

    def generate_block_list(self, state, level=0):
        """Generate the linear list of block permutations and assign offsets."""
        if len(self.depends) > 1:
            for _ in self.depends:
                index = random.randrange(len(self.depends))
                self.depends.append(self.depends.pop(index))

        for dependent in self.depends:
            while True:
                if dependent.generated or (dependent.once and random.randint(0, 1) == 0 and not dependent.last_reference()):
                    break

                dependent.generate_block_list(state, level + 1)

                if level != 0:
                    return

                for _ in self.depends:
                    index = random.randrange(len(self.depends))
                    self.depends.append(self.depends.pop(index))

        self.deref()
        self.state = state

        perm = self.rand_perm()

        self.offset = state.curr_offset
        self.generated = True

        state.curr_offset += perm.length
        state.block_list.append([self, perm])

        for block in self.next_blocks_list:
            block.generate_block_list(state)

        return state.block_list


class SymbolicBlockMeta(type):
    """Metaclass providing a debug-friendly repr for SymbolicBlock itself."""

    def __repr__(cls):
        """Return a debug-friendly representation of the SymbolicBlock namespace."""
        return "<SymbolicBlock: namespace for symbolic logical blocks (End)>"


class SymbolicBlock(SymbolicBlockMeta):
    """Contains symbolic logical blocks used in polymorphic buffer generation."""

    class End(LogicalBlock):
        """Represents the symbolic end of a polymorphic buffer."""

        def __init__(self):
            """Initialize the symbolic end block."""
            super().__init__("__SYMBLK_END__")
