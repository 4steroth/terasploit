import contextlib
import gzip
import html.parser
import json
import re
from dataclasses import dataclass, field
from typing import Any


# Scan pattern used by get_cookies() — mirrors Rex's regex.
_COOKIE_PAIR_RE: re.Pattern[str] = re.compile(r"\s?([^,;=\s]+?)=([^,;]*?)(?:[;,]|$)")

# Metadata attribute names filtered out of get_cookies().
_COOKIE_META_ATTRS: frozenset[str] = frozenset(["path", "expires", "domain", "max-age", "httponly", "secure", "samesite"])


class _MetaParser(html.parser.HTMLParser):
    """Minimal HTML parser that collects <meta> tag attributes."""

    def __init__(self) -> None:
        super().__init__()
        self.meta_tags: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "meta":
            self.meta_tags.append({k: (v or "") for k, v in attrs})


class _FormParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, str]] = []
        self._current: dict[str, str] = {}
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t == "form":
            self._in_form = True
            self._current = {}
        elif t == "input" and self._in_form:
            d = {k: (v or "") for k, v in attrs}
            if d.get("type", "").lower() == "hidden" and d.get("name"):
                self._current[d["name"]] = d.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._in_form:
            if self._current:
                self.forms.append(self._current)
            self._in_form = False


@dataclass
class Response:
    """
    Parsed HTTP response.

    Public API:
        .status_code  int
        .reason       str
        .proto        str    e.g. 'HTTP/1.1'
        .headers      dict   case-insensitive via _HeaderDict
        .body         bytes
        .text         str    (body decoded as latin-1)

    Parse a raw byte buffer with Response.parse(buf).
    """

    status_code: int = 200
    reason: str = "OK"
    proto: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    # Constructors

    @classmethod
    def parse(cls, raw: bytes):
        """Parse a raw HTTP response byte string."""
        res = cls()

        header_block, body_bytes = cls._split_headers_and_body(raw)
        lines = header_block.split(b"\r\n")
        if not lines:
            return res

        cls._parse_status_line(lines[0], res)

        headers = cls._parse_headers(lines[1:])
        res.headers = headers

        res.body = cls._decode_body(body_bytes, headers)

        return res

    @staticmethod
    def _split_headers_and_body(raw: bytes) -> tuple[bytes, bytes]:
        """Splits raw response bytes on the header/body separator, if present."""
        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            # Headers only, no body separator — try to parse what we have.
            return raw, b""
        return raw[:sep], raw[sep + 4 :]

    @staticmethod
    def _parse_status_line(line: bytes, res) -> None:
        """Parses the status line (e.g. 'HTTP/1.1 200 OK') into res, in place."""
        status_line = line.decode("latin-1", errors="replace")
        m = re.match(r"(HTTP/[\d.]+)\s+(\d{3})\s*(.*)", status_line)
        if m:
            res.proto = m.group(1)
            res.status_code = int(m.group(2))
            res.reason = m.group(3).strip()

    @staticmethod
    def _parse_headers(lines: list[bytes]) -> dict[str, str]:
        """Parses header lines into a dict, comma-joining repeated keys."""
        headers: dict[str, str] = {}
        for line in lines:
            decoded = line.decode("latin-1", errors="replace")
            if ":" not in decoded:
                continue
            k, _, v = decoded.partition(":")
            key = k.strip()
            val = v.strip()
            # Multi-value headers: comma-join (mirrors Ruby's header store)
            if key in headers:
                headers[key] = headers[key] + ", " + val
            else:
                headers[key] = val
        return headers

    @classmethod
    def _decode_body(cls, body_bytes: bytes, headers: dict[str, str]) -> bytes:
        """Decodes chunked transfer encoding and gzip content encoding, if present."""
        te = headers.get("Transfer-Encoding", "")
        body = cls._decode_chunked(body_bytes) if "chunked" in te.lower() else body_bytes

        # Auto-decode gzip Content-Encoding.
        ce = headers.get("Content-Encoding", "")
        if "gzip" in ce.lower():
            with contextlib.suppress(Exception):
                body = gzip.decompress(body)

        return body

    @staticmethod
    def _decode_chunked(data: bytes) -> bytes:
        """Decode a chunked-transfer-encoded body."""
        buf = b""
        remaining = data
        while remaining:
            crlf = remaining.find(b"\r\n")
            if crlf == -1:
                break
            size_str = remaining[:crlf].split(b";")[0].strip()
            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            start = crlf + 2
            buf += remaining[start : start + chunk_size]
            remaining = remaining[start + chunk_size + 2 :]
        return buf

    # Body helpers

    @property
    def text(self) -> str:
        """Decoded body string (latin-1)."""
        return self.body.decode("latin-1", errors="replace")

    def get_cookies(self) -> str:
        """Extract cookies from Set-Cookie headers as a 'key=value; ...' string."""
        raw = self.headers.get("Set-Cookie", "")
        if not raw:
            return ""

        parts: list[str] = []
        for m in _COOKIE_PAIR_RE.finditer(raw + ","):
            name = m.group(1)
            if name.lower() in _COOKIE_META_ATTRS:
                continue
            parts.append(f"{name}={m.group(2)}")

        return "; ".join(parts)

    def get_cookies_parsed(self) -> dict[str, list[str]]:
        """Return cookies as a dict of name → [value, ...] lists."""
        raw = self.headers.get("Set-Cookie", "")
        result: dict[str, list[str]] = {}
        if not raw:
            return result

        for m in _COOKIE_PAIR_RE.finditer(raw + ","):
            name = m.group(1)
            if name.lower() in _COOKIE_META_ATTRS:
                continue
            result.setdefault(name, []).append(m.group(2))

        return result

    def get_json_document(self) -> Any:
        """
        Parse the response body as JSON.
        Returns an empty dict on parse failure, mirroring Rex's behavior.
        """
        try:
            return json.loads(self.body)
        except json.JSONDecodeError, ValueError:
            return {}

    def get_html_meta_elements(self) -> list[dict[str, str]]:
        """Return a list of attribute dicts for every <meta> tag in the body."""
        parser = _MetaParser()
        with contextlib.suppress(Exception):
            parser.feed(self.text)

        return parser.meta_tags

    def get_hidden_inputs(self) -> list[dict[str, str]]:
        """Return hidden input values grouped by form."""
        p = _FormParser()
        with contextlib.suppress(Exception):
            p.feed(self.text)

        return p.forms

    def to_terminal_output(self, headers_only: bool = False) -> str:
        """Reconstruct the raw HTTP response as a printable string."""
        lines: list[str] = [f"{self.proto} {self.status_code} {self.reason}"]
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        output = "\r\n".join(lines) + "\r\n"

        if not headers_only and self.body:
            # Represent binary bodies as a hex summary rather than raw bytes
            # so the terminal output stays readable, mirroring MSF's behavior
            # of calling response.to_s which Ruby handles as binary-safe strings.
            try:
                body_str = self.body.decode("utf-8")
            except UnicodeDecodeError:
                body_str = f"<binary {len(self.body)} bytes>"
            output += "\r\n" + body_str

        return output

    # Dunder helpers

    def __bool__(self) -> bool:
        """Truthy when a valid HTTP status line was parsed."""
        return self.status_code != 0

    def __repr__(self) -> str:
        return f"<Response [{self.status_code} {self.reason}] headers={len(self.headers)} body={len(self.body)}b>"
