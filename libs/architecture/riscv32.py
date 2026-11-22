import contextlib


class RISCV32:
    """Provide RISCV32 register constants and validation helpers."""

    # Register number constants
    ZERO = X0 = 0  # constant 0
    RA = X1 = 1  # return address
    SP = X2 = 2  # stack pointer
    GP = X3 = 3  # global pointer
    TP = X4 = 4  # thread pointer
    T0 = X5 = 5  # temporary register 0
    T1 = X6 = 6  # temporary register 1
    T2 = X7 = 7  # temporary register 2
    S0 = FP = X8 = 8  # saved register / frame pointer
    S1 = X9 = 9  # saved register
    A0 = X10 = 10  # arg / return value
    A1 = X11 = 11  # arg / return value
    A2 = X12 = 12  # arg
    A3 = X13 = 13  # arg
    A4 = X14 = 14  # arg
    A5 = X15 = 15  # arg
    A6 = X16 = 16  # arg
    A7 = X17 = 17  # arg
    S2 = X18 = 18  # saved register
    S3 = X19 = 19  # saved register
    S4 = X20 = 20  # saved register
    S5 = X21 = 21  # saved register
    S6 = X22 = 22  # saved register
    S7 = X23 = 23  # saved register
    S8 = X24 = 24  # saved register
    S9 = X25 = 25  # saved register
    S10 = X26 = 26  # saved register
    S11 = X27 = 27  # saved register
    T3 = X28 = 28  # temporary register
    T4 = X29 = 29  # temporary register
    T5 = X30 = 30  # temporary register
    T6 = X31 = 31  # temporary register

    @staticmethod
    def reg_number(name: str) -> int:
        """Return the numeric ID associated with a named register."""
        with contextlib.suppress(AttributeError):
            return getattr(RISCV32, name.upper())

        raise ValueError(f"Unknown register: {name}") from None

    @staticmethod
    def check_reg(*regs: int) -> None:
        """Raise an error if any register number is outside the valid range."""
        for reg in regs:
            if not 0 <= reg <= 15:
                raise ValueError(f"Invalid register {reg}")
