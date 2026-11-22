import contextlib


class AMD64:
    """Provide AMD64 register constants and validation helpers."""

    # Register number constants.
    RAX = EAX = AX = AH = AL = 0  # accumulator
    RBX = EBX = BX = BH = BL = 1  # base
    RCX = ECX = CX = CH = CL = 2  # counter
    RDX = EDX = DX = DH = DL = 3  # data
    RSI = ESI = SI = 4  # source index
    RDI = EDI = DI = 5  # destination index
    RBP = EBP = BP = 6  # base pointer
    RSP = ESP = SP = 7  # stack pointer
    R8 = R8D = R8W = R8B = 8  # extended register
    R9 = R9D = R9W = R9B = 9
    R10 = R10D = R10W = R10B = 10
    R11 = R11D = R11W = R11B = 11
    R12 = R12D = R12W = R12B = 12
    R13 = R13D = R13W = R13B = 13
    R14 = R14D = R14W = R14B = 14
    R15 = R15D = R15W = R15B = 15

    @staticmethod
    def reg_number(name: str) -> int:
        """Return the numeric ID associated with a named register."""
        with contextlib.suppress(AttributeError):
            return getattr(AMD64, name.upper())

        raise ValueError(f"Unknown register: {name}") from None

    @staticmethod
    def check_reg(*regs: int) -> None:
        """Raise an error if any register number is outside the valid range."""
        for reg in regs:
            if not 0 <= reg <= 15:
                raise ValueError(f"Invalid register {reg}")
