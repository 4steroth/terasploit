# assembler.py - Public assembly API for terasm.
#
# Metasm-inspired design:
#   result = Assembler.assemble(cpu, "mov eax, 1; ret")
#   result.data        → bytes
#   result.hex         → hex string
#   result.insn_count  → int
#
# The Assembler class manages the libkeystone.so engine handle lifecycle
# transparently. Users never interact with raw handles.

from teralibs.tsf.pex.terasm import engine
from teralibs.tsf.pex.terasm.cpu import CPU
from teralibs.tsf.pex.terasm.terasm_const import (
    TA_API_MAJOR,
    TA_API_MINOR,
    TA_ERR_VERSION,
    TA_OPT_SYM_RESOLVER,
    TA_OPT_SYNTAX,
)


# This is required to be here since it uses terasm engine.
class TerasmError(Exception):
    """Raised when terasm encounters an assembly or engine error."""

    def __init__(self, errno, insn_count=None, message=None):
        self.errno = errno
        self.insn_count = insn_count
        # Allow callers to supply a richer message (e.g. version mismatch detail).
        # Fall back to the library's strerror when no override is given.
        self.message = message if message is not None else engine.strerror(errno)
        super().__init__(self.message)

    def __str__(self):
        return self.message


# Result object


class EncodedData:
    """Result of a successful assembly operation."""

    __slots__ = ("addr", "data", "hex", "insn_count")

    def __init__(self, data: bytes, insn_count: int, addr: int):
        self.data = data
        self.hex = data.hex() if data else ""
        self.insn_count = insn_count
        self.addr = addr

    def __repr__(self):
        return f"<EncodedData insns={self.insn_count} bytes={len(self.data)} hex={self.hex!r}>"

    def __len__(self):
        return len(self.data)

    def __bytes__(self):
        return self.data


class Assembler:
    """Engine handle wrapper. One instance per arch/mode/syntax combination."""

    def __init__(self, cpu):
        """Open an engine handle for the given CPU descriptor."""

        # Verify binary compatibility before touching the handle
        major, minor, _ = engine.lib_version()
        if major != TA_API_MAJOR or minor != TA_API_MINOR:
            raise TerasmError(
                TA_ERR_VERSION,
                message=(f"libkeystone.so version mismatch: expected {TA_API_MAJOR}.{TA_API_MINOR}, got {major}.{minor}"),
            )

        self._cpu = cpu
        self._handle = engine.open_engine(cpu.arch, cpu.mode)
        self._sym_resolver_ref = None  # keeps the ctypes callback alive

        # Apply syntax if the CPU specifies one
        if cpu.syntax is not None:
            engine.set_option(self._handle, TA_OPT_SYNTAX, cpu.syntax)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        """Explicitly release the engine handle."""
        if self._handle is not None:
            engine.close_engine(self._handle)
            self._handle = None

    def __del__(self):
        # Guard against __init__ raising before self._handle was assigned
        if hasattr(self, "_handle"):
            self.close()

    @property
    def syntax(self):
        """Current syntax option value."""
        return self._cpu.syntax

    @syntax.setter
    def syntax(self, style):
        """Change the assembly syntax on the live handle."""
        engine.set_option(self._handle, TA_OPT_SYNTAX, style)
        # Reconstruct via the CPU subclass constructor to preserve the type.
        # namedtuple._replace() returns the base namedtuple type, not CPU.

        self._cpu = CPU(
            arch=self._cpu.arch,
            mode=self._cpu.mode,
            syntax=style,
            name=self._cpu.name,
        )

    @property
    def sym_resolver(self):
        """Return sym resolver."""
        return self._sym_resolver_ref

    @sym_resolver.setter
    def sym_resolver(self, resolver):
        """Set a symbol resolver callback."""
        cb = engine.TA_SYM_RESOLVER(resolver)
        engine.set_option(self._handle, TA_OPT_SYM_RESOLVER, cb)
        # Hold a reference so ctypes does not garbage-collect the callback
        self._sym_resolver_ref = cb

    # Assembly - instance method

    def asm(self, source: str | bytes, addr: int = 0) -> EncodedData:
        """Assemble one or more instructions and return an EncodedData result."""
        if isinstance(source, str):
            source = source.encode("ascii")

        raw, insn_count = engine.assemble_raw(self._handle, source, addr)

        if raw is None:
            return EncodedData(b"", 0, addr)

        return EncodedData(raw, insn_count, addr)

    # Assembly - class-level factory (primary metasm-style entry point)

    @classmethod
    def assemble(cls, cpu, source: str, addr: int = 0) -> EncodedData:
        """Assemble source for the given CPU and return an EncodedData result."""
        with cls(cpu) as asm:
            return asm.asm(source, addr)
