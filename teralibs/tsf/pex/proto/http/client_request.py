import io
import ipaddress
import pathlib
import random
import uuid
from collections.abc import Mapping
from typing import Any

from teralibs.tsf.pex.text import Text
from teralibs.tsf.pex.user_agent import UserAgent


# Constants
DEFAULT_USER_AGENT = UserAgent.most_common()


def _is_ipv6(host: str) -> bool:
    """Check if the host is a valid ipv6"""
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
    except ValueError:
        return False


class MimeMessage:
    """Minimal multipart/form-data builder."""

    def __init__(self) -> None:
        self.bound: str = uuid.uuid4().hex
        self._parts: list[dict[str, Any]] = []

    def add_part(self, data: str, mime_type: str | None, encoding: str | None, content_disposition: str) -> None:
        """Add a part to the multipart message."""
        self._parts.append(
            {
                "data": data,
                "mime_type": mime_type,
                "encoding": encoding,
                "content_disposition": content_disposition,
            }
        )

    def to_s(self) -> str:
        """Return the complete multipart message as a string."""
        buf = ""
        for part in self._parts:
            buf += f"--{self.bound}\r\n"
            buf += f"Content-Disposition: {part['content_disposition']}\r\n"
            if part["mime_type"]:
                buf += f"Content-Type: {part['mime_type']}\r\n"
            if part["encoding"]:
                buf += f"Content-Transfer-Encoding: {part['encoding']}\r\n"
            buf += "\r\n"
            buf += part["data"]
            buf += "\r\n"
        buf += f"--{self.bound}--\r\n"
        return buf


class ClientRequest:
    """
    Builds a raw HTTP request string from a configuration dict.

    Supports CGI parameter encoding, multipart form-data, chunked transfer
    encoding, header manipulation, and a range of evasion techniques.

    Usage::

        req = ClientRequest(
            {
                "method": "POST",
                "uri": "/login",
                "vhost": "example.com",
                "vars_post": {"user": "admin", "pass": "secret"},
            }
        )
        raw = str(req)  # full request
        hdrs = req.build(headers_only=True)
    """

    DEFAULT_CONFIG: Mapping[str, Any] = {
        # Regular HTTP
        "agent": None,
        "cgi": True,
        "cookie": None,
        "data": "",
        "headers": None,
        "raw_headers": "",
        "method": "GET",
        "partial": False,
        "path_info": "",
        "port": 80,
        "proto": "HTTP",
        "query": "",
        "ssl": False,
        "uri": "/",
        "vars_get": {},
        "vars_post": {},
        "vars_form_data": [],
        "version": "1.1",
        "vhost": None,
        "ssl_server_name_indication": None,
        # Evasion options
        "encode_params": True,
        "encode": False,
        "uri_encode_mode": "hex-normal",
        "uri_encode_count": 1,
        "uri_full_url": False,
        "pad_method_uri_count": 1,
        "pad_uri_version_count": 1,
        "pad_method_uri_type": "space",  # space | tab | apache
        "pad_uri_version_type": "space",  # space | tab | apache
        "method_random_valid": False,
        "method_random_invalid": False,
        "method_random_case": False,
        "version_random_valid": False,
        "version_random_invalid": False,
        "uri_dir_self_reference": False,
        "uri_dir_fake_relative": False,
        "uri_use_backslashes": False,
        "pad_fake_headers": False,
        "pad_fake_headers_count": 16,
        "pad_get_params": False,
        "pad_get_params_count": 8,
        "pad_post_params": False,
        "pad_post_params_count": 8,
        "uri_fake_end": False,
        "uri_fake_params_start": False,
        "shuffle_get_params": False,
        "shuffle_post_params": False,
        "header_folding": False,
        "chunked_size": 0,
        # NTLM options
        "usentlm2_session": True,
        "use_ntlmv2": True,
        "send_lm": True,
        "send_ntlm": True,
        "SendSPN": True,
        "UseLMKey": False,
        "domain": "WORKSTATION",
        # Digest options
        "DigestAuthIIS": True,
    }

    def __init__(self, opts: dict[str, Any] | None = None) -> None:
        self.opts: dict[str, Any] = {**self.DEFAULT_CONFIG, **(opts or {})}
        if not self.opts.get("agent"):
            self.opts["agent"] = DEFAULT_USER_AGENT
        if self.opts.get("headers") is None:
            self.opts["headers"] = {}

    def build(self, headers_only: bool = False) -> str:
        """Build and return the complete HTTP request string."""
        qstr = self.opts.get("query") or ""
        pstr = self.opts.get("data") or ""
        ctype = self.opts.get("ctype")

        if self.opts["cgi"]:
            uri_str = self._set_uri()
            qstr, pstr, ctype = self._build_cgi_params(qstr, pstr, ctype)
        else:
            if self.opts["encode"]:
                qstr = self._set_encode_uri(qstr)
            uri_str = self._set_uri()

        req = ""
        req += self._set_method()
        req += self._set_method_uri_spacer()
        req += self._set_uri_prepend()

        if self.opts["encode"]:
            req += self._set_encode_uri(uri_str)
        else:
            req += uri_str

        if qstr:
            req += "?" + qstr

        req += self._set_path_info()
        req += self._set_uri_append()
        req += self._set_uri_version_spacer()
        req += self._set_version()

        header_keys_lower = {k.lower() for k in self.opts.get("headers", {})}

        if "host" not in header_keys_lower:
            req += self._set_host_header()

        if "user-agent" not in header_keys_lower:
            req += self._set_agent_header()

        if "authorization" not in header_keys_lower:
            req += self._set_auth_header()

        req += self._set_cookie_header()
        req += self._set_connection_header()
        req += self._set_extra_headers()
        req += self._set_content_type_header(ctype)
        req += self._set_content_len_header(len(pstr))
        req += self._set_chunked_header()
        req += self.opts.get("raw_headers", "")

        if not headers_only:
            req += self._set_body(pstr)

        return req

    def __str__(self) -> str:
        return self.build()

    def _build_cgi_params(self, qstr: str, pstr: str, ctype: str | None) -> tuple[str, str, str | None]:
        """Build GET query string and POST body from vars_get / vars_post / vars_form_data options."""
        qstr = self._pad_get_params(qstr)
        qstr = self._append_vars_get(qstr)
        pstr = self._pad_post_params(pstr)
        pstr = self._append_vars_post(pstr)
        pstr = self._append_form_data(pstr)
        ctype = self._resolve_content_type(ctype)
        return qstr, pstr, ctype

    def _pad_get_params(self, qstr: str) -> str:
        """Appends padded random GET params per pad_get_params / pad_get_params_count."""
        if not self.opts.get("pad_get_params"):
            return qstr
        for _ in range(int(self.opts["pad_get_params_count"])):
            if qstr:
                qstr += "&"
            qstr += self._set_encode_uri(Text.rand_text_alphanumeric(random.randint(1, 32)))
            qstr += "="
            qstr += self._set_encode_uri(Text.rand_text_alphanumeric(random.randint(1, 32)))
        return qstr

    def _append_vars_get(self, qstr: str) -> str:
        """Appends vars_get key/value pairs to the GET query string, optionally shuffled/encoded."""
        vars_get: dict = self.opts.get("vars_get") or {}
        if not vars_get:
            return qstr

        if self.opts.get("shuffle_get_params"):
            items = list(vars_get.items())
            random.shuffle(items)
            vars_get = dict(items)

        for var, val in vars_get.items():
            var = str(var)
            if qstr:
                qstr += "&"
            qstr += self._set_encode_uri(var) if self.opts["encode_params"] else var
            # Support params with no value (e.g. ?flag)
            if val is not None:
                qstr += "="
                qstr += self._set_encode_uri(str(val)) if self.opts["encode_params"] else str(val)

        return qstr

    def _pad_post_params(self, pstr: str) -> str:
        """Appends padded random POST params per pad_post_params / pad_post_params_count."""
        if not self.opts.get("pad_post_params"):
            return pstr
        for _ in range(int(self.opts["pad_post_params_count"])):
            rand_var = Text.rand_text_alphanumeric(random.randint(1, 32))
            rand_val = Text.rand_text_alphanumeric(random.randint(1, 32))
            if pstr:
                pstr += "&"
            pstr += self._set_encode_uri(rand_var) if self.opts["encode_params"] else rand_var
            pstr += "="
            pstr += self._set_encode_uri(rand_val) if self.opts["encode_params"] else rand_val
        return pstr

    def _append_vars_post(self, pstr: str) -> str:
        """Appends vars_post key/value(s) to the POST body, optionally shuffled/encoded."""
        vars_post: dict = self.opts.get("vars_post") or {}
        if self.opts.get("shuffle_post_params"):
            items = list(vars_post.items())
            random.shuffle(items)
            vars_post = dict(items)

        for var, val in vars_post.items():
            var = str(var)
            val_list: list = val if isinstance(val, list) else [val]
            for v in val_list:
                v = str(v)
                if pstr:
                    pstr += "&"
                pstr += self._set_encode_uri(var) if self.opts["encode_params"] else var
                pstr += "="
                pstr += self._set_encode_uri(v) if self.opts["encode_params"] else v

        return pstr

    def _append_form_data(self, pstr: str) -> str:
        """Appends multipart/form-data encoded vars_form_data fields to the POST body."""
        vars_form_data = self.opts.get("vars_form_data")
        if not vars_form_data:
            return pstr

        if not isinstance(vars_form_data, list):
            raise ValueError(f"_build_cgi_params: vars_form_data must be a list, got {type(vars_form_data).__name__}")

        form_data = MimeMessage()
        # Reuse boundary across calls to ensure idempotency
        if not self.opts.get("vars_form_data_boundary"):
            self.opts["vars_form_data_boundary"] = form_data.bound
        form_data.bound = self.opts["vars_form_data_boundary"]

        for field_hash in vars_form_data:
            field_name = field_hash.get("name", None)
            if field_name is not None and not isinstance(field_name, str):
                raise ValueError(f"_build_cgi_params: field name must be str or None, got {type(field_name).__name__}")

            mime_type = field_hash.get("content_type", None)
            encoding = field_hash.get("encoding", None)
            file_contents = self._get_file_data(field_hash.get("data"))
            filename = field_hash.get("filename", self._get_filename(field_hash.get("data")))

            content_disposition = "form-data"
            if field_name is not None:
                content_disposition += f'; name="{field_name}"'
            # Intentionally unescaped — exploit payloads may be embedded
            # in the filename (e.g. playsms_filename_exec).
            if filename is not None:
                content_disposition += f'; filename="{filename}"'

            form_data.add_part(file_contents, mime_type, encoding, content_disposition)

        pstr += form_data.to_s()
        return pstr

    def _resolve_content_type(self, ctype: str | None) -> str | None:
        """Determines Content-Type when not explicitly set, from form-data boundary or method."""
        if not ctype and self.opts.get("vars_form_data_boundary"):
            ctype = f"multipart/form-data; boundary={self.opts['vars_form_data_boundary']}"
        if not ctype and self.opts.get("method") == "POST":
            ctype = "application/x-www-form-urlencoded"
        return ctype

    def _set_uri(self) -> str:
        uri_str = self.opts["uri"]

        if self.opts.get("uri_dir_self_reference"):
            uri_str = uri_str.replace("/", "/./")

        if self.opts.get("uri_dir_fake_relative"):
            buf = ""
            for part in uri_str.split("/"):
                cnt = random.randint(2, 9)
                for _ in range(cnt):
                    buf += "/" + Text.rand_text_alphanumeric(random.randint(1, 32))
                buf += "/.." * cnt
                buf += "/" + part
            uri_str = buf

        if self.opts.get("uri_full_url"):
            scheme = "https" if self.opts.get("ssl") else "http"
            url = f"{scheme}://{self.opts['vhost']}"
            if self.opts["port"] != 80:
                url += f":{self.opts['port']}"
            url += uri_str
            return url

        return uri_str

    def _set_encode_uri(self, s: str) -> str:
        a = str(s)
        for _ in range(int(self.opts["uri_encode_count"])):
            a = Text.uri_encode(a, self.opts["uri_encode_mode"])
        return a

    def _set_method(self) -> str:
        ret = self.opts["method"]

        if self.opts.get("method_random_valid"):
            ret = random.choice(["GET", "POST", "HEAD"])

        if self.opts.get("method_random_invalid"):
            ret = Text.rand_text_alpha(random.randint(1, 20))

        if self.opts.get("method_random_case"):
            ret = Text.to_rand_case(ret)

        return ret

    def _set_method_uri_spacer(self) -> str:
        return self._build_spacer(
            int(self.opts["pad_method_uri_count"]),
            self.opts.get("pad_method_uri_type", "space"),
        )

    def _set_uri_prepend(self) -> str:
        prefix = ""
        if self.opts.get("uri_fake_params_start"):
            prefix += "/%3fa=b/../"
        if self.opts.get("uri_fake_end"):
            prefix += "/%20HTTP/1.0/../../"
        return prefix

    def _set_path_info(self) -> str:
        return self.opts.get("path_info") or ""

    def _set_uri_append(self) -> str:
        # Reserved for future padding types
        return ""

    def _set_uri_version_spacer(self) -> str:
        return self._build_spacer(
            int(self.opts["pad_uri_version_count"]),
            self.opts.get("pad_uri_version_type", "space"),
        )

    def _build_spacer(self, length: int, pad_type: str) -> str:
        """Build a padding string of the requested length and character set."""
        if pad_type == "tab":
            charset = "\t"
        elif pad_type == "apache":
            charset = "\t \x0b\x0c\x0d"
        else:
            charset = " "

        buf = ""
        while len(buf) < length:
            buf += random.choice(charset)
        return buf

    def _set_version(self) -> str:
        ret = f"{self.opts['proto']}/{self.opts['version']}"

        if self.opts.get("version_random_valid"):
            ret = f"{self.opts['proto']}/{random.choice(['1.0', '1.1'])}"

        if self.opts.get("version_random_invalid"):
            ret = Text.rand_text_alphanumeric(random.randint(1, 20))

        return ret + "\r\n"

    def _set_formatted_header(self, var: str, val: str) -> str:
        # header_folding inserts a CRLF + TAB for legacy IDS evasion
        if self.opts.get("header_folding"):
            return f"{var}:\r\n\t{val}\r\n"
        return f"{var}: {val}\r\n"

    def _set_agent_header(self) -> str:
        agent = self.opts.get("agent")
        return self._set_formatted_header("User-Agent", agent) if agent else ""

    def _set_auth_header(self) -> str:
        auth = self.opts.get("authorization")
        return self._set_formatted_header("Authorization", auth) if auth else ""

    def _set_cookie_header(self) -> str:
        cookie = self.opts.get("cookie")
        return self._set_formatted_header("Cookie", cookie) if cookie else ""

    def _set_connection_header(self) -> str:
        conn = self.opts.get("connection")
        return self._set_formatted_header("Connection", conn) if conn else ""

    def _set_content_type_header(self, ctype: str | None) -> str:
        return self._set_formatted_header("Content-Type", ctype) if ctype else ""

    def _set_content_len_header(self, clen: int) -> str:
        # RFC-7230: omit Content-Length on GET with no body or chunked encoding.
        # POST always includes it, even when zero.
        if self.opts["method"] == "GET" and (clen == 0 or self.opts.get("chunked_size", 0) > 0):
            return ""
        # Respect a caller-supplied Content-Length; don't emit a duplicate.
        if self.opts.get("headers", {}).get("Content-Length"):
            return ""
        return self._set_formatted_header("Content-Length", str(clen))

    def _set_host_header(self) -> str:
        if self.opts.get("uri_full_url"):
            # Host is already encoded in the request URI
            return ""

        host = self.opts.get("vhost") or ""

        if _is_ipv6(host):
            host = f"[{host}]"

        if self.opts["port"] not in (80, 443):
            host = f"{host}:{self.opts['port']}"

        return self._set_formatted_header("Host", host)

    def _set_extra_headers(self) -> str:
        buf = ""

        if self.opts.get("pad_fake_headers"):
            for _ in range(int(self.opts["pad_fake_headers_count"])):
                buf += self._set_formatted_header(
                    Text.rand_text_alphanumeric(random.randint(1, 32)),
                    Text.rand_text_alphanumeric(random.randint(1, 32)),
                )

        for var, val in self.opts.get("headers", {}).items():
            buf += self._set_formatted_header(var, val)

        return buf

    def _set_chunked_header(self) -> str:
        if not self.opts.get("chunked_size"):
            return ""
        return self._set_formatted_header("Transfer-Encoding", "chunked")

    def _set_body(self, bdata: str) -> str:
        if not self.opts.get("chunked_size"):
            return "\r\n" + bdata

        # Chunked transfer encoding: split body into random-sized chunks
        chunks = ""
        remaining = bdata
        chunk_max = self.opts["chunked_size"]
        while remaining:
            size = random.randint(1, chunk_max)
            chunk = remaining[:size]
            remaining = remaining[size:]
            chunks += format(len(chunk), "x") + "\r\n" + chunk + "\r\n"

        return "\r\n" + chunks + "0\r\n\r\n"

    @staticmethod
    def _get_file_data(data: Any) -> str:
        """Read file-like objects; return string data directly."""
        if hasattr(data, "read"):
            data.seek(0)
            contents = data.read()
            data.seek(0)
            return contents if isinstance(contents, str) else contents.decode("latin-1")
        return str(data) if data is not None else ""

    @staticmethod
    def _get_filename(data: Any) -> str | None:
        """Extract a basename from Path or file objects."""
        if isinstance(data, (pathlib.Path, io.IOBase)):
            name = getattr(data, "name", None) or str(data)
            return pathlib.Path(name).name
        return None
