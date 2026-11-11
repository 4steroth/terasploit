import re


# Matches \xNN escape sequences OR bare two-digit hex tokens that are
# not part of a longer hex run (e.g. prevents "deadbeef" from matching).
_HEX_TOKEN = re.compile(
    r"\\x([0-9a-fA-F]{2})"
    r"|(?<![0-9a-fA-F])([0-9a-fA-F]{2})(?![0-9a-fA-F])"
)


class BadCharScanResult:
    """Result of scanning a byte sequence for bad characters."""

    def __init__(self, hits, payload_length, clean=None, bad_bytes_found=None):
        """Initialise a BadCharScanResult."""
        self.hits = hits
        self.payload_length = payload_length
        self.bad_bytes_found = bad_bytes_found if bad_bytes_found is not None else frozenset(v for _, v in hits)
        self.clean = clean if clean is not None else len(hits) == 0

    def summary(self):
        """Return a one-line human-readable summary of the scan result."""
        if self.clean:
            return f"payload is clean ({self.payload_length} bytes)"

        distinct = " ".join(f"\\x{b:02x}" for b in sorted(self.bad_bytes_found))
        return f"{len(self.bad_bytes_found)} bad byte(s) found in {self.payload_length}-byte payload ({distinct})"

    def offsets_for(self, byte_value):
        """Return a sorted list of payload offsets where *byte_value* was found."""
        return [offset for offset, bval in self.hits if bval == byte_value]

    def as_set_string(self):
        """Return a \\xNN-formatted string of all unique bad bytes found."""
        return " ".join(f"\\x{b:02x}" for b in sorted(self.bad_bytes_found))


class BadCharFilter:
    """Utility class for parsing, scanning, and visualising bad-character sets."""

    @staticmethod
    def parse(raw):
        """Parse a BADCHARS string into a frozenset of byte integers."""
        if not raw:
            return frozenset()

        bad = set()
        for match in _HEX_TOKEN.finditer(raw):
            hex_str = match.group(1) or match.group(2)
            value = int(hex_str, 16)
            if not 0 <= value <= 255:
                raise ValueError(f"Byte value 0x{value:x} is out of range (0-255).")
            bad.add(value)

        return frozenset(bad)

    @staticmethod
    def scan(payload, bad_bytes):
        """Scan *payload* for occurrences of bytes in *bad_bytes*."""
        hits = [(offset, byte) for offset, byte in enumerate(payload) if byte in bad_bytes]

        return BadCharScanResult(hits=hits, payload_length=len(payload))

    @staticmethod
    def is_clean(payload, bad_bytes):
        """Return True when *payload* contains none of the bytes in *bad_bytes*."""
        return not any(byte in bad_bytes for byte in payload)

    @staticmethod
    def format_hits(result):
        """Return a formatted string listing every bad-byte hit."""
        if result.clean:
            return "No bad bytes found."

        parts = [f"Offset 0x{offset:04x} ({offset}): \\x{byte:02x}" for offset, byte in result.hits]
        lines = ["  ".join(parts[i : i + 8]) for i in range(0, len(parts), 8)]

        return "\n".join(lines)

    @staticmethod
    def byte_map(bad_bytes):
        """Return a 16*16 hex grid with bad bytes marked as xx."""
        rows = []
        for row in range(16):
            cells = []
            for col in range(16):
                byte = row * 16 + col
                cells.append("xx" if byte in bad_bytes else f"{byte:02x}")
            rows.append(" ".join(cells))

        header = f"Bad bytes map  (xx = bad, {len(bad_bytes)} bad byte(s) total):"
        return header + "\n" + "\n".join(rows)

    @staticmethod
    def hex_dump(payload, bad_bytes):
        """Return an annotated hex dump with bad bytes wrapped in [XX]."""
        if not payload:
            return "(empty payload)"

        rows = []
        for row_start in range(0, len(payload), 16):
            chunk = payload[row_start : row_start + 16]

            tokens = []
            for byte in chunk:
                if byte in bad_bytes:
                    tokens.append(f"[{byte:02x}]")
                else:
                    tokens.append(f" {byte:02x} ")
            rows.append(f"0x{row_start:04x}  {''.join(tokens)}")

        return "\n".join(rows)
