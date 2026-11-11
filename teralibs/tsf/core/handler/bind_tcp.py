import contextlib
import dataclasses
import socket
import time
from typing import Any


CONNECT_TIMEOUT: float = 100.0
HANDLER_TYPE: str = "bind"


@dataclasses.dataclass
class _RawConnection:
    sock: Any
    addr: tuple[str, int]


class BindTcpHandler:
    """Connects to a port already listening on the target machine."""

    HANDLER_TYPE = HANDLER_TYPE

    def __init__(
        self,
        rhost: str,
        rport: int,
        timeout: float = CONNECT_TIMEOUT,
        delay: float = 2.0,
        retry_count: int = 1,
        retry_wait: float = 5.0,
        ctx: Any = None,
        exploit_ctx: Any = None,
    ) -> None:
        self.rhost = rhost
        self.rport = int(rport)
        self.timeout = timeout
        self.delay = delay
        self.retry_count = retry_count
        self.retry_wait = retry_wait
        self.ctx = ctx
        self.exploit_ctx = exploit_ctx
        self._sock = None
        self._error: str | None = None

    # Factory

    @classmethod
    def from_datastore(cls, datastore, timeout: float = CONNECT_TIMEOUT, opts: dict | None = None):
        """Construct from framework datastore values."""
        opts = opts or {}

        rhost = datastore.get_value("RHOST") or datastore.get_value("LHOST")
        rport = datastore.get_value("RPORT") or datastore.get_value("LPORT")

        if not rhost:
            raise ValueError("RHOST must be set for bind_tcp handler.")
        if not rport:
            raise ValueError("RPORT/LPORT must be set for bind_tcp handler.")

        return cls(
            rhost=rhost,
            rport=int(rport),
            timeout=timeout,
            delay=float(opts.get("delay", 2.0)),
            retry_count=int(opts.get("retry_count", 1)),
            retry_wait=float(opts.get("retry_wait", 5.0)),
            ctx=opts.get("ctx"),
            exploit_ctx=opts.get("exploit_ctx"),
        )

    def start(self) -> None:
        """No-op — bind handler prepares nothing before the exploit fires."""

    def wait(self, _result: Any = None) -> _RawConnection | None:
        """Connect to the target's bind listener with retry support."""
        if self.exploit_ctx is not None:
            self.exploit_ctx.info(f"Connecting to bind listener at {self.rhost}:{self.rport}...")

        attempts = max(1, self.retry_count)
        for attempt in range(1, attempts + 1):
            if self.ctx is not None and self.ctx.is_killed():
                return None

            conn = self._connect()
            if conn is not None:
                return conn

            if attempt < attempts:
                if self.exploit_ctx is not None:
                    self.exploit_ctx.warning(f"Bind connect failed (attempt {attempt}/{attempts}), retrying in {self.retry_wait}s...")
                time.sleep(self.retry_wait)

        if self.exploit_ctx is not None:
            self.exploit_ctx.error(f"Bind connect failed after {attempts} attempt(s). {self._error or ''}")
        return None

    def stop(self) -> None:
        """Close the socket if it was never handed to a session."""
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None

    def get_error(self) -> str | None:
        """Return the last connection error, if any."""
        return self._error

    def _connect(self) -> _RawConnection | None:
        """Single connection attempt with delay and keepalive."""
        self._error = None

        if self.delay > 0:
            time.sleep(self.delay)

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.rhost, self.rport))
            sock.settimeout(None)
            self._set_keepalive(sock)
            self._sock = sock
            return _RawConnection(sock=sock, addr=(self.rhost, self.rport))

        except (TimeoutError, OSError) as exc:
            self._error = str(exc)
            if sock:
                with contextlib.suppress(OSError):
                    sock.close()
            return None

    @staticmethod
    def _set_keepalive(sock: socket.socket) -> None:
        """Enable TCP keepalive on the socket with platform-specific options."""
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
