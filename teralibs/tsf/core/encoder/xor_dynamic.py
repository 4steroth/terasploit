from teralibs.tsf.core.module.base import Base


class XorDynamic(Base):
    """x64 single-byte XOR encoder"""

    def __init__(self):
        super().__init__()

        self.register_advanced_options(
            [
                self.opt(
                    "KEYMIN",
                    "0",
                    False,
                    "Minimum key length",
                    self.otype.INTEGER,
                ),
                self.opt(
                    "KEYMAX",
                    "255",
                    False,
                    "Maximum key length",
                    self.otype.INTEGER,
                ),
                self.opt(
                    "KEYINC",
                    "1",
                    False,
                    "Key increment",
                    self.otype.INTEGER,
                ),
            ]
        )

    def stub(self) -> bytes:
        """Returns the static decoder stub bytes."""
        return (
            b"\xeb\x27"  #        jmp    _call
            + b"\x5b"  # _ret:  pop    rbx
            + b"\x53"  #        push   rbx
            + b"\x5f"  #        pop    rdi
            + b"\xb0\x41"  #        mov    al, 'A'
            + b"\xfc"  #        cld
            + b"\xae"  # _lp1:  scas   al, BYTE PTR es:[rdi]
            + b"\x75\xfd"  #        jne    _lp1
            + b"\x57"  #        push   rdi
            + b"\x59"  #        pop    rcx
            + b"\x53"  # _lp2:  push   rbx
            + b"\x5e"  #        pop    rsi
            + b"\x8a\x06"  # _lp3:  mov    al, BYTE PTR [rsi]
            + b"\x30\x07"  #        xor    BYTE PTR [rdi], al
            + b"\x48\xff\xc7"  #        inc    rdi
            + b"\x48\xff\xc6"  #        inc    rsi
            + b"\x66\x81\x3f\x42\x42"  #        cmp    WORD PTR [rdi], 'BB'
            + b"\x74\x07"  #        je     _jmp
            + b"\x80\x3e\x41"  #        cmp    BYTE PTR [rsi], 'A'
            + b"\x75\xea"  #        jne    _lp3
            + b"\xeb\xe6"  #        jmp    _lp2
            + b"\xff\xe1"  # _jmp:  jmp    rcx
            + b"\xe8\xd4\xff\xff\xff"  # _call: call   _ret
        )

    def stub_key_term(self) -> bytes:
        """Returns the static bytes used to identify the key and terminate the stub."""
        return b"A"

    def stub_payload_term(self) -> bytes:
        """Returns the static bytes used to identify the payload and terminate the stub."""
        return b"BB"

    def min_key_len(self) -> int:
        """Returns the minimum key length (number of bytes) to attempt when encoding."""
        return int(self.DATASTORE.get("KEYMIN") or 0)

    def max_key_len(self) -> int:
        """Returns the maximum key length (number of bytes) to attempt when encoding."""
        return int(self.DATASTORE.get("KEYMAX") or 255)

    def key_inc(self) -> int:
        """Returns the key increment (step) to use when iterating key candidates."""
        return int(self.DATASTORE.get("KEYINC") or 1)
