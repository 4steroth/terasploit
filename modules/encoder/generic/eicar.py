from collections.abc import Sequence

from teralibs.tsf.base.encoder import Encoder, EncoderRank, EncoderResult


class TerasploitModule(Encoder):
    """
    This is a simple encoder that replaces the given payload with the EICAR test string.
    The EICAR test string is a standard string used to test antivirus software.
    It is designed to trigger antivirus alerts without being harmful.
    """

    NAME: str = "Eicar"
    DESCRIPTION: str = (
        "This encoder merely replaces the given payload with the EICAR test string. "
        "Note, this is sure to ruin your payload. "
        "Any content-aware firewall, proxy, IDS, or IPS that follows anti-virus "
        "standards should alert and do what it would normally do when malware is "
        "transmitted across the wire. "
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: int = EncoderRank.MANUAL
    REFERENCES: Sequence = []

    def eicar_test_string(self) -> str:
        """Generates the standard EICAR antivirus test string."""

        obfus_eicar = [
            "x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar",
            "standard",
            "antivirus",
            "test",
            "file!$h+h*",
        ]
        return "-".join(obfus_eicar).upper()

    def encode(
        self,
        raw_bytes: bytes,
        bad_bytes: frozenset[int],
        ctx: object | None = None,
    ):
        """Encodes the given raw bytes by replacing them with the EICAR test string."""

        eicar_string = self.eicar_test_string()
        return EncoderResult(
            success=True,
            encoded_bytes=eicar_string.encode(),
            encoder_name=self.NAME,
            key_used=None,
        )

    def can_avoid(self, bad_bytes: frozenset[int]) -> bool:
        return True
