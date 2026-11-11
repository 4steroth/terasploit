import contextlib


class ZARCH:
    """Provide ZARCH register constants and validation helpers."""

    # Register number constants
    R0 = 0  # general purpose, often scratch
    R1 = 1  # general purpose, sometimes function arg
    R2 = 2  # function argument / return value
    R3 = 3  # function argument
    R4 = 4  # function argument
    R5 = 5  # function argument
    R6 = 6  # function argument
    R7 = 7  # function argument
    R8 = 8  # callee-saved / local variable
    R9 = 9  # callee-saved / local variable
    R10 = 10  # callee-saved / local variable
    R11 = 11  # callee-saved / local variable
    R12 = 12  # callee-saved / local variable
    R13 = 13  # callee-saved / local variable
    R14 = LR = 14  # link register (return address)
    R15 = SP = 15  # stack pointer / base register

    @staticmethod
    def reg_number(name: str) -> int:
        """Return the numeric ID associated with a named register."""
        with contextlib.suppress(AttributeError):
            return getattr(ZARCH, name.upper())

        raise ValueError(f"Unknown register: {name}") from None

    @staticmethod
    def check_reg(*regs: int) -> None:
        """Raise an error if any register number is outside the valid range."""
        for reg in regs:
            if not 0 <= reg <= 15:
                raise ValueError(f"Invalid register {reg}")
