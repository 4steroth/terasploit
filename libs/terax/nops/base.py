from collections.abc import Mapping
from typing import Literal


class NopStrategy:
    """Mixin that dispatches NOP generation to editable architecture strategies."""

    name = "base"
    strategy_methods: Mapping = {"fixed-width": "generate_fixed_width"}
    default_strategy = "fixed-width"

    @classmethod
    def available_strategies(cls):
        """Return the strategy names implemented by this architecture."""
        return tuple(cls.strategy_methods)

    @classmethod
    def generate(cls, length, badchars=(), byteorder=None, strategy=None):
        """Dispatch NOP generation to the selected architecture strategy."""
        selected = str(strategy or cls.default_strategy).strip().lower()

        method_name = cls.strategy_methods.get(selected)
        if method_name is None:
            allowed = ", ".join(cls.available_strategies())
            raise ValueError(f"{cls.name} supports NOP strategy: {allowed}")

        return getattr(cls, method_name)(length, badchars, byteorder)


class FixedWidthNop(NopStrategy):
    """Generate a repeated, fixed-width instruction encoding."""

    name = "unknown"
    instruction = b""
    alignment = 1
    default_byteorder: Literal["little", "big"] = "little"
    byteorders = ("little", "big")
    strategy_methods: Mapping = {"fixed-width": "generate_fixed_width"}
    default_strategy = "fixed-width"

    @classmethod
    def generate_fixed_width(cls, length, badchars=(), byteorder=None):
        """Return an aligned fixed-width NOP sequence satisfying byte constraints."""
        cls._validate_length(length)
        if length == 0:
            return b""

        order = (byteorder or cls.default_byteorder).lower()
        if order not in cls.byteorders:
            allowed = ", ".join(cls.byteorders)
            raise ValueError(f"{cls.name} supports byte order: {allowed}")
        if length % cls.alignment:
            raise ValueError(f"NOP sled length {length} is not aligned to the {cls.alignment}-byte {cls.name} instruction width")

        instruction = cls.instruction
        if order != cls.default_byteorder:
            instruction = int.from_bytes(instruction, cls.default_byteorder).to_bytes(len(instruction), order)

        forbidden = cls._normalize_badchars(badchars)
        conflicts = sorted(set(instruction) & forbidden)
        if conflicts:
            rendered = ", ".join(f"0x{byte:02x}" for byte in conflicts)
            raise ValueError(f"the {cls.name} NOP instruction contains forbidden byte(s): {rendered}")
        return instruction * (length // cls.alignment)

    @staticmethod
    def _validate_length(length):
        """Validate a requested NOP sled length."""
        if isinstance(length, bool) or not isinstance(length, int):
            raise TypeError("NOP sled length must be an integer")
        if length < 0:
            raise ValueError("NOP sled length cannot be negative")

    @staticmethod
    def _normalize_badchars(badchars):
        """Normalize bytes-like or integer-iterable bad-character input."""
        if badchars is None:
            return frozenset()
        if isinstance(badchars, (str, int, bool)):
            raise TypeError("bad characters must be bytes or an iterable of integer byte values")
        try:
            values = bytes(badchars)
        except TypeError, ValueError:
            raise TypeError("bad characters must contain integer values from 0 to 255") from None
        return frozenset(values)

    def __repr__(self):
        """Return a concise representation of the NOP generator."""
        return f"{type(self).__name__}()"
