import base64
import contextlib
import dataclasses
import socket
import ssl as ssl_socket
from typing import Any

from teralibs.tsf.pex.proto.http.client_request import ClientRequest
from teralibs.tsf.pex.proto.http.response import Response
from teralibs.tsf.pex.user_agent import UserAgent
from teralibs.tsf.utils.exception import HttpClientError


# 1 MB default read cap — mirrors Rex's read_max_data default.
READ_MAX_DATA: int = 1024 * 1024

# Default connect/read timeout in seconds.
DEFAULT_TIMEOUT: int = 20


@dataclasses.dataclass
class HttpParam:
    """
    This class holds all http client parameter.

    >>> rhost = (host, port)
    >>> ssl_info = (False, "Version)
    """

    # rhost = (host, port)
    rhost: tuple[str, int]
    ssl_info: tuple[bool, str | None] = (False, None)
    timeout: int = DEFAULT_TIMEOUT
    proxies: str | None = None
    username: str = ""
    password: str = ""
    sslkeylogfile: str | None = None


class HttpClient:
    """Raw-socket HTTP client."""

    def __init__(self, param: HttpParam) -> None:
        self.param = param

        # Active TCP or TLS socket — None when disconnected.
        self.conn: socket.socket | ssl_socket.SSLSocket | None = None

        # Optional Kerberos authenticator — set by ExploitHttpClient.connect()
        # when HTTP::Auth == kerberos.  When set, _send_auth calls
        # authenticator.authenticate() on a 401 Negotiate challenge instead
        # of falling through to Basic.
        self.authenticator: Any = None

        # Persistent config dict merged into every ClientRequest.
        self.config: dict[str, Any] = {
            **ClientRequest.DEFAULT_CONFIG,
            "read_max_data": READ_MAX_DATA,
            "vhost": self.param.rhost[0],
            "ssl_server_name_indication": self.param.rhost[0],
            "agent": UserAgent.most_common(),
        }

    # Config

    def set_config(self, opts: dict[str, Any]) -> None:
        """Merge opts into the persistent config."""
        self.config.update(opts)

    # Request builders

    def request_raw(self, opts: dict[str, Any] | None = None) -> ClientRequest:
        """Build a non-CGI request."""
        merged = {**self.config, **(opts or {})}
        merged["cgi"] = False
        merged["port"] = self.param.rhost[1]
        merged["ssl"] = self.param.ssl_info[0]
        return ClientRequest(merged)

    def request_cgi(self, opts: dict[str, Any] | None = None) -> ClientRequest:
        """Build a CGI-compatible request."""
        merged = {**self.config, **(opts or {})}
        merged["cgi"] = True
        merged["port"] = self.param.rhost[1]
        merged["ssl"] = self.param.ssl_info[0]
        return ClientRequest(merged)

    # Transport

    def connect(self, timeout: int | None = None) -> socket.socket | ssl_socket.SSLSocket:
        """Open a TCP (or TLS) connection to the target."""
        if self.conn is not None:
            return self.conn

        t = timeout if timeout is not None else self.param.timeout
        try:
            raw = socket.create_connection((self.param.rhost[0], self.param.rhost[1]), timeout=t)
        except OSError as exc:
            raise HttpClientError(f"Connection to {self.param.rhost[0]}:{self.param.rhost[1]} failed: {exc}") from exc

        self.conn = self._wrap_ssl(raw) if self.param.ssl_info[0] else raw
        return self.conn

    def _wrap_ssl(self, raw: socket.socket) -> ssl_socket.SSLSocket:
        """Wrap a raw socket in TLS, respecting ssl_version and SNI."""
        ctx = ssl_socket.SSLContext(ssl_socket.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl_socket.CERT_NONE

        version_map: dict[str, ssl_socket.TLSVersion] = {
            "TLSv1": ssl_socket.TLSVersion.TLSv1,
            "TLSv1_1": ssl_socket.TLSVersion.TLSv1_1,
            "TLSv1_2": ssl_socket.TLSVersion.TLSv1_2,
            "TLSv1_3": ssl_socket.TLSVersion.TLSv1_3,
        }
        if self.param.ssl_info[1] and self.param.ssl_info[1] in version_map:
            ver = version_map[self.param.ssl_info[1]]
            ctx.minimum_version = ver
            ctx.maximum_version = ver

        if self.param.sslkeylogfile:
            ctx.keylog_filename = self.param.sslkeylogfile

        sni = self.config.get("ssl_server_name_indication") or self.param.rhost[0]
        try:
            return ctx.wrap_socket(raw, server_hostname=sni)
        except ssl_socket.SSLError as exc:
            raw.close()
            raise HttpClientError(f"TLS handshake with {self.param.rhost[0]}:{self.param.rhost[1]} failed: {exc}") from exc

    def close(self) -> None:
        """Shut down and close the active connection."""
        if self.conn is not None:
            with contextlib.suppress(OSError):
                self.conn.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self.conn.close()
            self.conn = None

    def send_recv(self, req: ClientRequest, timeout: int | None = None, persist: bool = False) -> Response | None:
        """Send a ClientRequest and read the response."""
        res = self._send_recv(req, timeout, persist)
        if res is not None and res.status_code == 401 and res.headers.get("WWW-Authenticate"):
            res = self._send_auth(res, req.opts, timeout, persist)

        return res

    def _send_recv(self, req: ClientRequest, timeout: int | None = None, _persist: bool = False) -> Response | None:
        """Low-level send + read. Does not handle auth."""
        t = timeout if timeout is not None else self.param.timeout
        self._send_request(req, t)
        return self._read_response(t)

    def _send_request(self, req: ClientRequest, timeout: int | None = None) -> None:
        """Connect (if needed) and write the raw request string to the socket."""
        self.connect(timeout)
        raw_bytes = str(req).encode("latin-1")
        try:
            if self.conn:
                self.conn.sendall(raw_bytes)
        except OSError as exc:
            self.conn = None
            raise HttpClientError(f"Send to {self.param.rhost[0]}:{self.param.rhost[1]} failed: {exc}") from exc

    def _read_response(self, timeout: int | None = None) -> Response | None:
        """Read an HTTP response from the active socket and parse it."""
        if self.conn is None:
            return None

        t = timeout if timeout is not None else self.param.timeout
        self.conn.settimeout(t)

        buf = b""
        try:
            while True:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if _response_complete(buf):
                    break

        except TimeoutError:
            pass  # Return partial read if headers are present.

        except OSError:
            self.conn = None
            return None

        return Response.parse(buf) if buf else None

    def _send_auth(
        self,
        res: Response,
        opts: dict[str, Any],
        timeout: int | None,
        persist: bool,
    ) -> Response | None:
        """
        Retry the request with the appropriate auth scheme on a 401.

        Kerberos (Negotiate): calls self.authenticator.authenticate() to
        obtain a SPNEGO token, injects Authorization: Negotiate <token>,
        and retries.  Only attempted when self.authenticator is set and
        the server offers 'Negotiate' in WWW-Authenticate.

        Basic: falls back to base64 credentials when preferred_auth is
        None or 'Basic' and 'Basic' is offered.

        NTLM/Digest are handled at the ExploitHttpClient layer.
        """
        auth_header = res.headers.get("WWW-Authenticate", "")
        preferred = opts.get("preferred_auth")

        # Kerberos / Negotiate
        if self.authenticator is not None and "Negotiate" in auth_header and preferred in (None, "Kerberos"):
            try:
                token = self.authenticator.authenticate()
            except Exception as exc:
                raise HttpClientError(f"Kerberos authentication failed: {exc}") from exc

            retry_opts = {
                **opts,
                "headers": {
                    **(opts.get("headers") or {}),
                    "Authorization": f"Negotiate {token}",
                },
            }
            return self._send_recv(self.request_cgi(retry_opts), timeout, persist)

        # Basic
        username = opts.get("username") or self.param.username
        password = opts.get("password") or self.param.password

        if not username:
            return res

        if "Basic" in auth_header and preferred in (None, "Basic"):
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            retry_opts = {
                **opts,
                "headers": {
                    **(opts.get("headers") or {}),
                    "Authorization": f"Basic {token}",
                },
            }
            return self._send_recv(self.request_cgi(retry_opts), timeout, persist)

        return res

    def __enter__(self):
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_val: BaseException | None,
        _exc_tb: Any,
    ) -> None:
        self.close()


def _response_complete(buf: bytes) -> bool:
    """Heuristic: decide whether a raw byte buffer contains a complete HTTP response."""
    header_end = buf.find(b"\r\n\r\n")
    if header_end == -1:
        return False

    header_block = buf[:header_end].decode("latin-1", errors="replace")
    body = buf[header_end + 4 :]

    headers_lower: dict[str, str] = {}
    for line in header_block.splitlines()[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers_lower[k.strip().lower()] = v.strip()

    te = headers_lower.get("transfer-encoding", "")
    if "chunked" in te.lower():
        return buf.endswith(b"0\r\n\r\n")

    cl = headers_lower.get("content-length")
    if cl is not None:
        try:
            return len(body) >= int(cl)

        except ValueError:
            return True

    return True
