import contextlib


class ARM:
    """Provide ARM register constants and validation helpers."""

    # Register number constants
    R0 = A1 = 0  # function argument / return value
    R1 = A2 = 1  # function argument
    R2 = A3 = 2  # function argument
    R3 = A4 = 3  # function argument
    R4 = V1 = 4  # variable / callee-saved
    R5 = V2 = 5  # variable / callee-saved
    R6 = V3 = 6  # variable / callee-saved
    R7 = V4 = 7  # variable / callee-saved
    R8 = V5 = 8  # variable / callee-saved
    R9 = V6 = SB = 9  # static base / callee-saved
    R10 = V7 = SL = 10  # stack limit / callee-saved
    R11 = V8 = FP = 11  # frame pointer
    R12 = IP = 12  # intra-procedure scratch
    R13 = SP = 13  # stack pointer
    R14 = LR = 14  # link register (return address)
    R15 = PC = 15  # program counter

    @staticmethod
    def reg_number(name: str) -> int:
        """Return the numeric ID associated with a named register."""
        with contextlib.suppress(AttributeError):
            return getattr(ARM, name.upper())

        raise ValueError(f"Unknown register: {name}") from None

    @staticmethod
    def check_reg(*regs: int) -> None:
        """Raise an error if any register number is outside the valid range."""
        for reg in regs:
            if not 0 <= reg <= 15:
                raise ValueError(f"Invalid register {reg}")
