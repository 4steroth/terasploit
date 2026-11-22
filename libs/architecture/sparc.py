import struct
from collections.abc import Mapping


class SPARC:
    """Provide SPARC register constants and validation helpers."""

    # Register number constants
    REGISTER_NUMBER: Mapping[str, int] = {
        "g0": 0,
        "g1": 1,
        "g2": 2,
        "g3": 3,
        "g4": 4,
        "g5": 5,
        "g6": 6,
        "g7": 7,
        "o0": 8,
        "o1": 9,
        "o2": 10,
        "o3": 11,
        "o4": 12,
        "o5": 13,
        "o6": 14,
        "o7": 15,
        "l0": 16,
        "l1": 17,
        "l2": 18,
        "l3": 19,
        "l4": 20,
        "l5": 21,
        "l6": 22,
        "l7": 23,
        "i0": 24,
        "i1": 25,
        "i2": 26,
        "i3": 27,
        "i4": 28,
        "i5": 29,
        "i6": 30,
        "i7": 31,
        "sp": 14,
        "fp": 30,
    }

    @classmethod
    def sethi(cls, constant: int, dst: str) -> bytes:
        """Encodes a SETHI instruction with the value 'constant' being put into 'dst' register."""
        instruction = ((cls.REGISTER_NUMBER[dst] << 25) | (4 << 22) | (constant >> 10)) & 0xFFFFFFFF
        return struct.pack(">I", instruction)

    @classmethod
    def ori(cls, src: str, constant: int, dst: str) -> bytes:
        """Encodes an OR instruction with the value 'constant' being OR'ed with the 'src' register into the 'dst' register."""
        instruction = (
            (2 << 30) | (cls.REGISTER_NUMBER[dst] << 25) | (2 << 19) | (cls.REGISTER_NUMBER[src] << 14) | (1 << 13) | (constant & 0x1FFF)
        ) & 0xFFFFFFFF
        return struct.pack(">I", instruction)

    @classmethod
    def set_dword(cls, constant: int, dst: str) -> bytes:
        """Puts 'constant' into the 'dst' register using both sethi and ori."""
        return cls.sethi(constant, dst) + cls.ori(dst, constant & 0x3FF, dst)

    @classmethod
    def set_val(cls, constant: int, dst: str) -> bytes:
        """Puts 'constant' into the 'dst' register using as few instructions as possible by checking the size of the value."""
        if 0 <= constant <= 4095:
            return cls.ori("g0", constant, dst)
        elif (constant & 0x3FF) != 0:
            return cls.set_dword(constant, dst)
        else:
            return cls.sethi(constant, dst)
