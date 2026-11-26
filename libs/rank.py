import enum


class Rank(enum.StrEnum):
    """Contains all the valid module ranking of terasploit"""

    MANUAL = "manual"
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    GREAT = "great"
    EXCELLENT = "excellent"


class EncoderRank(enum.IntEnum):
    """Numeric rank for encoder quality, used to sort the selection pipeline."""

    MANUAL = 0
    LOW = 100
    NORMAL = 200
    GOOD = 300
    GREAT = 400
    EXCELLENT = 500

    def label(self) -> str:
        """Return the capitalised rank name (e.g. 'Excellent')."""
        return self.name.capitalize()
