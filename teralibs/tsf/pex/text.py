import base64
import html
import random
import re
import secrets
import string
import struct
import urllib.parse
from urllib.parse import unquote_plus


# Constants

ALL_CHARS = bytes(range(1, 256))
ALPHA_LOWER = b"abcdefghijklmnopqrstuvwxyz"
ALPHA_UPPER = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NUMERIC = b"0123456789"
HEX_LOWER = b"0123456789abcdef"

ALL_CHARS_STR = string.ascii_letters + string.digits + string.punctuation
ALPHA_UPPER_STR = string.ascii_uppercase
ALPHA_LOWER_STR = string.ascii_lowercase
NUMERIC_STR = string.digits
HEX_LOWER_STR = string.hexdigits.lower()[:16]


class Hash:
    """Hash integer utilities."""

    @staticmethod
    def ror(dword: int, bits: int) -> int:
        """Rotate a 32-bit unsigned integer right by cnt bits."""
        dword &= 0xFFFFFFFF
        bits &= 31

        return ((dword >> bits) | (dword << (32 - bits))) & 0xFFFFFFFF

    @staticmethod
    def ror13_hash(name: str | bytes) -> int:
        """Calculate the ROR13 hash of a given string."""
        data = name if isinstance(name, bytes) else name.encode("latin-1")
        hash_val = 0

        for byte in data:
            hash_val = Hash.ror(hash_val, 13)
            hash_val += byte

        return hash_val

    @classmethod
    def ror13(cls, value):
        """Performs a 32-bit rotate-right by 13 bits."""
        value &= 0xFFFFFFFF
        return ((value >> 13) | (value << 19)) & 0xFFFFFFFF

    @classmethod
    def block_api_hash(cls, module_name: str, function_name: str, iv: int = 0) -> str:
        """Recreates Rex::Text.block_api_hash parsing technique."""
        api_hash = iv & 0xFFFFFFFF

        module_upper = module_name.upper()
        module_bytes = module_upper.encode("utf-16le")

        for byte in module_bytes:
            api_hash = cls.ror13(api_hash)
            api_hash = (api_hash + byte) & 0xFFFFFFFF

        function_bytes = function_name.encode("ascii") + b"\x00"

        for byte in function_bytes:
            api_hash = cls.ror13(api_hash)
            api_hash = (api_hash + byte) & 0xFFFFFFFF

        return f"0x{api_hash:08X}"


class Uri:
    """Uri text utilities"""

    @staticmethod
    def uri_decode(data):
        """Decode a URI-encoded string."""
        return unquote_plus(data)

    @staticmethod
    def uri_decode_bytes(data):
        """Decode a URI-encoded bytes."""
        if not isinstance(data, bytes):
            return data

        decoded = unquote_plus(data.decode("latin-1"))
        return decoded.encode("latin-1")

    @staticmethod
    def uri_encode(value: str, mode: str = "hex-normal") -> str:
        """Percent-encode a string using the specified encoding mode."""
        if mode in ("hex-all", "hex-noslashes", "hex-normal"):
            safe = {
                "hex-all": "",
                "hex-noslashes": "/",
                "hex-normal": "/-_.~",
            }.get(mode, "/-_.~")

            return urllib.parse.quote(value, safe=safe)

        if mode in ("hex-random", "u-random"):
            unicode_mode = mode == "u-random"

            def encode_random(char: str) -> str:
                """Randomly encode a character."""
                if random.random() <= 0.5:
                    return char

                if unicode_mode:
                    return f"%u{ord(char):04X}"

                return urllib.parse.quote(char, safe="")

            return "".join(encode_random(char) for char in value)

        if mode in ("u-all", "u-noslashes", "u-normal"):
            safe = {
                "u-all": set(),
                "u-noslashes": {"/"},
                "u-normal": set("/-_.~"),
            }[mode]

            return "".join(char if char in safe else f"%u{ord(char):04X}" for char in value)

        return urllib.parse.quote(value, safe="/-_.~")


class Rand:
    """Random text utilities."""

    @staticmethod
    def to_bytes(val: bytes | str) -> bytes:
        """Convert a string or bytes value to bytes."""
        return val.encode("latin-1") if isinstance(val, str) else val

    @staticmethod
    def rand_char(bad: bytes | str = b"", chars: bytes = ALL_CHARS) -> bytes:
        """Generate a random character from the specified character set."""
        return Rand.rand_text(1, bad, chars)

    @staticmethod
    def rand_base(length: int | range, bad: bytes | str, *charsets: bytes | str) -> bytes:
        """Generate random bytes from the supplied character sets."""
        excluded = set(Rand.to_bytes(bad))

        charsets_bytes = b"".join(Rand.to_bytes(charset) for charset in charsets)
        charset = list(dict.fromkeys(char for char in charsets_bytes if char not in excluded))

        if not charset:
            return b""

        if isinstance(length, range):
            length = random.randrange(length.start, length.stop)

        return bytes(random.choices(charset, k=length))

    @staticmethod
    def rand_base_str(length: int | range, bad: str, *chars: str) -> str:
        """Generate random text using the specified character sets."""
        charset = "".join(chars)
        charset = "".join(char for char in charset if char not in bad)

        if not charset:
            raise ValueError("Character set cannot be empty after excluding bad characters")
        size = secrets.choice(range(length.start, length.stop)) if isinstance(length, range) else length

        return "".join(secrets.choice(charset) for _ in range(size))

    @staticmethod
    def rand_text_str(length: int | range, bad: str = "", chars: str = ALL_CHARS_STR) -> str:
        """Generate random text using the specified character set."""
        return Rand.rand_base_str(length, bad, chars)

    @staticmethod
    def rand_text_alpha_str(length: int | range, bad: str = "") -> str:
        """Generate random alphabetic text."""
        return Rand.rand_base_str(length, bad, ALPHA_UPPER_STR, ALPHA_LOWER_STR)

    @staticmethod
    def rand_text_alpha_lower_str(length: int | range, bad: str = "") -> str:
        """Generate random lowercase alphabetic text."""
        return Rand.rand_base_str(length, bad, ALPHA_LOWER_STR)

    @staticmethod
    def rand_text_alpha_upper_str(length: int | range, bad: str = "") -> str:
        """Generate random uppercase alphabetic text."""
        return Rand.rand_base_str(length, bad, ALPHA_UPPER_STR)

    @staticmethod
    def rand_text_alphanumeric_str(length: int | range, bad: str = "") -> str:
        """Generate random alphanumeric text."""
        return Rand.rand_base_str(length, bad, ALPHA_UPPER_STR, ALPHA_LOWER_STR, NUMERIC_STR)

    @staticmethod
    def rand_case_str(length: int | range, bad: str = "") -> str:
        """Generate random alphabetic text in random cases."""
        return Rand.rand_base_str(length, bad, ALPHA_UPPER_STR, ALPHA_LOWER_STR)

    @staticmethod
    def rand_text_hex_str(length: int | range, bad: str = "") -> str:
        """Generate random lowercase hexadecimal text."""
        return Rand.rand_base_str(length, bad, HEX_LOWER_STR)

    @staticmethod
    def rand_text_numeric_str(length: int | range, bad: str = "") -> str:
        """Generate random numeric text."""
        return Rand.rand_base_str(length, bad, NUMERIC_STR)

    @staticmethod
    def rand_text(length: int | range, bad: bytes | str = b"", chars: bytes = ALL_CHARS) -> bytes:
        """Generate random bytes using the specified character set."""
        return Rand.rand_base(length, bad, chars)

    @staticmethod
    def rand_text_alpha(length: int | range, bad: bytes | str = b"") -> bytes:
        """Generate random alphabetic bytes."""
        return Rand.rand_base(length, bad, ALPHA_UPPER, ALPHA_LOWER)

    @staticmethod
    def rand_text_alpha_lower(length: int | range, bad: bytes | str = b"") -> bytes:
        """Generate random lowercase alphabetic bytes."""
        return Rand.rand_base(length, bad, ALPHA_LOWER)

    @staticmethod
    def rand_text_alpha_upper(length: int | range, bad: bytes | str = b"") -> bytes:
        """Generate random uppercase alphabetic bytes."""
        return Rand.rand_base(length, bad, ALPHA_UPPER)

    @staticmethod
    def rand_text_alphanumeric(length: int | range, bad: bytes | str = b"") -> bytes:
        """Generate random alphanumeric bytes."""
        return Rand.rand_base(length, bad, ALPHA_UPPER, ALPHA_LOWER, NUMERIC)

    @staticmethod
    def rand_text_hex(length: int | range, bad: bytes | str = b"") -> bytes:
        """Generate random lowercase hexadecimal bytes."""
        return Rand.rand_base(length, bad, HEX_LOWER)

    @staticmethod
    def rand_text_numeric(length: int | range, bad: bytes | str = b"") -> bytes:
        """Generate random numeric bytes."""
        return Rand.rand_base(length, bad, NUMERIC)

    @staticmethod
    def rand_4byte_utf8() -> bytes:
        """Generate a valid random four-byte UTF-8 character."""
        codepoint = random.randint(0x10000, 0x10FFFF)
        return struct.pack(
            ">BBBB",
            0xF0 | (codepoint >> 18),
            0x80 | ((codepoint >> 12) & 0x3F),
            0x80 | ((codepoint >> 6) & 0x3F),
            0x80 | (codepoint & 0x3F),
        )


class Text(Hash, Rand, Uri):
    """Python text library."""

    @staticmethod
    def badchar_index(data, badchars):
        """Return the index of the first bad character, or None."""
        if not badchars:
            return None

        if isinstance(badchars, (set, frozenset)):
            badchars = bytes(badchars)

        for index, (byte,) in enumerate(struct.iter_unpack("B", data)):
            if byte in badchars:
                return index

        return None

    @staticmethod
    def strip_tags(text: str, tag, leading_whitespace) -> str:
        """
        Remove HTML tags from a string.
        >>> return Text.strip_tags(html, tag=r"</?[^>]*>", leading_whitespace=r"^\\s+")
        """
        text = html.unescape(text)
        text = re.compile(tag).sub("", text)
        text = re.compile(leading_whitespace, re.MULTILINE).sub("", text)
        return text.strip()

    @staticmethod
    def encode_base64(text):
        """Encode text in base64."""
        return base64.b64encode(text.encode()).decode()

    @staticmethod
    def xor(key: bytes, value: bytes) -> bytes:
        """XOR a byte sequence against a repeating key."""
        if not key or not value:
            raise ValueError("XOR operations require non-empty keys and values.")

        key_len = len(key)
        return bytes(byte ^ key[i % key_len] for i, byte in enumerate(value))

    @staticmethod
    def to_hex(data: bytes, prefix: str = "\\x") -> str:
        """Converts a byte stream into an escaped hex string (e.g., \\x90\\xcc)."""
        if isinstance(data, str):
            data = data.encode("utf-8")

        return "".join(f"{prefix}{b:02x}" for b in data)

    @staticmethod
    def to_hex_cstring(data: bytes, bytes_per_line: int = 15) -> str:
        """Converts raw bytes into a C-style double-quoted formatted string block."""
        if isinstance(data, str):
            data = data.encode("utf-8")

        if not data:
            return '""'

        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i : i + bytes_per_line]
            hex_chunk = "".join(f"\\x{b:02x}" for b in chunk)
            lines.append(f'"{hex_chunk}"')

        return "\n".join(lines)

    @staticmethod
    def to_rand_case_str(chars) -> str:
        """Return the text with randomly assigned character casing."""
        return "".join(char.upper() if secrets.randbelow(2) else char.lower() for char in chars)
