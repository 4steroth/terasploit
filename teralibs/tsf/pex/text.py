import base64
import html
import random
import re
import string
import urllib.parse
from urllib.parse import unquote_plus


# Constants

NUMERALS = "0123456789"
ALPHA_UPPER = string.ascii_uppercase
ALPHA_LOWER = string.ascii_lowercase
ALPHANUMERIC = string.ascii_letters + NUMERALS


class Text:
    """Python text library."""

    # Text Encoding

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
    def uri_encode(s: str, mode: str = "hex-normal") -> str:
        """
        Percent-encode a string using the specified mode.

        Modes mirror Rex::Text.uri_encode:
        hex-normal    — encode unsafe chars as %XX, leave / and common safe chars
        hex-all       — encode every character as %XX
        hex-noslashes — encode everything except /
        hex-random    — randomly encode each character
        u-normal      — unicode %uXXXX for unsafe chars
        u-all         — unicode %uXXXX for all chars
        u-noslashes   — unicode %uXXXX, leave /
        u-random      — randomly apply unicode encoding

        Unrecognised modes fall back to hex-normal.
        """
        if mode == "hex-all":
            result = urllib.parse.quote(s, safe="")
        elif mode == "hex-noslashes":
            result = urllib.parse.quote(s, safe="/")
        elif mode == "hex-random":
            result = "".join(urllib.parse.quote(c, safe="") if random.random() > 0.5 else c for c in s)
        elif mode == "u-all":
            result = "".join(f"%u{ord(c):04X}" for c in s)
        elif mode == "u-noslashes":
            result = "".join(c if c == "/" else f"%u{ord(c):04X}" for c in s)
        elif mode == "u-normal":
            safe = set("/-_.~")
            result = "".join(c if c in safe else f"%u{ord(c):04X}" for c in s)
        elif mode == "u-random":
            result = "".join(f"%u{ord(c):04X}" if random.random() > 0.5 else c for c in s)
        else:
            # "hex-normal" and the fallback for unknown modes
            result = urllib.parse.quote(s, safe="/-_.~")
        return result

    @staticmethod
    def encode_base64(text):
        """Encode text in base64."""
        return base64.b64encode(text.encode()).decode()

    # HTML

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

    # Algorithmic Hash Routines

    @staticmethod
    def ror(val: int, cnt: int) -> int:
        """Rotate a 32-bit unsigned integer right by cnt bits."""
        val &= 0xFFFFFFFF
        return ((val >> cnt) | (val << (32 - cnt))) & 0xFFFFFFFF

    @staticmethod
    def ror13_hash(name: str | bytes) -> int:
        """
        Calculate the ROR13 hash of a given string.
        Matches Rex::Text.ror13_hash behavior exactly.
        """
        data = name if isinstance(name, bytes) else name.encode("latin-1")
        hash_val = 0

        for byte in data:
            hash_val = Text.ror(hash_val, 13)
            hash_val += byte

        return hash_val

    @classmethod
    def ror13(cls, value):
        """
        Performs a 32-bit rotate-right by 13 bits.

        This matches the primitive used by Metasploit's
        block_api resolver:

            ror reg, 13
            add reg, byte
        """
        value &= 0xFFFFFFFF
        return ((value >> 13) | (value << 19)) & 0xFFFFFFFF

    @classmethod
    def block_api_hash(cls, module_name: str, function_name: str, iv: int = 0) -> str:
        """Recreates Metasploit's Rex::Text.block_api_hash parsing technique."""
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

    # Random Payload/Obfuscation Injections

    @staticmethod
    def rand_text(length: int, bad_chars: str = "", chars: str = ALPHANUMERIC) -> str:
        """
        Generates a randomized string of a given length from a character set,
        ensuring elements from a bad character block are filtered out.
        """
        # Automatically unpack byte strings if passed as bad character filters
        if isinstance(bad_chars, (bytes, bytearray)):
            bad_chars = bad_chars.decode("utf-8", errors="ignore")

        # Purge bad characters from the generation pool
        charset = [c for c in chars if c not in bad_chars]
        if not charset:
            raise ValueError("Character pool exhausted after filtering bad characters.")

        return "".join(random.choice(charset) for _ in range(length))

    @classmethod
    def rand_text_hex(cls, length: int, bad_chars: str = "") -> str:
        """Generates random lowercase hexadecimal strings."""
        return cls.rand_text(length, bad_chars, chars="0123456789abcdef")

    @classmethod
    def rand_text_alphanumeric(cls, length: int, bad_chars: str = "") -> str:
        """Generates random alphanumeric strings."""
        return cls.rand_text(length, bad_chars, chars=ALPHANUMERIC)

    @classmethod
    def rand_text_alpha(cls, length: int, bad_chars: str = "") -> str:
        """Generates random alphabetic lowercase/uppercase strings."""
        return cls.rand_text(length, bad_chars, chars=string.ascii_letters)

    @classmethod
    def rand_text_numeric(cls, length: int, bad_chars: str = "") -> str:
        """Generates random numeric-only string buffers."""
        return cls.rand_text(length, bad_chars, chars=NUMERALS)

    @staticmethod
    def to_rand_case(s: str) -> str:
        """Randomly converts characters in a string to uppercase or lowercase."""
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    # Encoding & Formatting Utilities

    @staticmethod
    def to_hex(data: bytes, prefix: str = "\\x") -> str:
        """Converts a byte stream into an escaped hex string (e.g., \\x90\\xcc)."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        return "".join(f"{prefix}{b:02x}" for b in data)

    @staticmethod
    def to_hex_cstring(data: bytes, bytes_per_line: int = 15) -> str:
        """
        Converts raw bytes into a C-style double-quoted formatted string block.
        Slices based on the number of raw payload bytes required per line layout.
        """
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

    # Buffer Operations

    @staticmethod
    def xor(key: bytes, value: bytes) -> bytes:
        """
        XORs a byte sequence against a variable-length tracking key value.
        """
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(value, str):
            value = value.encode("utf-8")

        if not key or not value:
            raise ValueError("XOR operations require non-empty keys and value payloads.")

        key_len = len(key)
        return bytes(value[i] ^ key[i % key_len] for i in range(len(value)))
