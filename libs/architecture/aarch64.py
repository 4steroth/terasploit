import contextlib


class AARCH64:
    """Provide AARCH64 register constants and validation helpers."""

    # Register number constants.
    X0 = W0 = 0  # function arg / return value
    X1 = W1 = 1  # function arg / return value
    X2 = W2 = 2  # function arg
    X3 = W3 = 3  # function arg
    X4 = W4 = 4  # function arg
    X5 = W5 = 5  # function arg
    X6 = W6 = 6  # function arg
    X7 = W7 = 7  # function arg
    X8 = W8 = 8  # indirect result location (a.k.a. "indirect result" / sometimes "XR")
    X9 = W9 = 9  # temporary
    X10 = W10 = 10  # temporary
    X11 = W11 = 11  # temporary
    X12 = W12 = 12  # temporary
    X13 = W13 = 13  # temporary
    X14 = W14 = 14  # temporary
    X15 = W15 = 15  # temporary
    X16 = W16 = 16  # intra-procedure call scratch (IP0)
    X17 = W17 = 17  # intra-procedure call scratch (IP1)
    X18 = W18 = 18  # platform register (reserved by OS)
    X19 = W19 = 19  # callee-saved
    X20 = W20 = 20  # callee-saved
    X21 = W21 = 21  # callee-saved
    X22 = W22 = 22  # callee-saved
    X23 = W23 = 23  # callee-saved
    X24 = W24 = 24  # callee-saved
    X25 = W25 = 25  # callee-saved
    X26 = W26 = 26  # callee-saved
    X27 = W27 = 27  # callee-saved
    X28 = W28 = 28  # callee-saved
    X29 = W29 = FP = 29  # frame pointer
    X30 = W30 = LR = 30  # link register (return address)
    SP = 31  # stack pointer (shares encoding with XZR/WZR)
    XZR = WZR = 31  # zero register (reads as 0, writes ignored)

    @staticmethod
    def reg_number(name: str) -> int:
        """Return the numeric ID associated with a named register."""
        with contextlib.suppress(AttributeError):
            return getattr(AARCH64, name.upper())

        raise ValueError(f"Unknown register: {name}") from None

    @staticmethod
    def check_reg(*regs: int) -> None:
        """Raise an error if any register number is outside the valid range."""
        for reg in regs:
            if not 0 <= reg <= 15:
                raise ValueError(f"Invalid register {reg}")
