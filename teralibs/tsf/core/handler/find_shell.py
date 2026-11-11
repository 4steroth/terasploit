import contextlib
import dataclasses
import socket
import time
from typing import Any, cast

import paramiko

from teralibs.tsf.pex.text import Text


VERIFY_TIMEOUT: float = 5.0
_POST_STAGE_SLEEP: float = 1.5
HANDLER_TYPE: str = "find"


@dataclasses.dataclass
class _RawConnection:
    sock: Any
    addr: tuple[str, int]


class FindShellHandler:
    """Validates a pre-existing socket or SSH channel as a live shell via an echo probe."""

    HANDLER_TYPE = HANDLER_TYPE

    def __init__(self, timeout: float = VERIFY_TIMEOUT, ctx: Any = None, exploit_ctx: Any = None) -> None:
        self.timeout = timeout
        self.ctx = ctx
        self.exploit_ctx = exploit_ctx
        self._error: str | None = None

    @classmethod
    def from_datastore(cls, _datastore, timeout: float = VERIFY_TIMEOUT, opts: dict | None = None):
        """Construct from framework datastore values."""
        opts = opts or {}
        return cls(
            timeout=timeout,
            ctx=opts.get("ctx"),
            exploit_ctx=opts.get("exploit_ctx"),
        )

    def start(self) -> None:
        """No-op — FindShell opens no listener."""

    def wait(self, result: Any = None) -> _RawConnection | None:
        """Verify that result (a socket or SSH channel from module.run()) has a live shell."""
        self._error = None

        if not isinstance(result, (socket.socket, paramiko.Channel)):
            self._error = "No socket or SSH channel returned from exploit."
            if self.exploit_ctx is not None:
                self.exploit_ctx.error(self._error)
            return None

        if self.exploit_ctx is not None:
            self.exploit_ctx.info("FindShell: verifying shell on supplied socket...")

        try:
            # paramiko.Channel.getpeername() is typed to allow a bare str
            # fallback ("unknown") for exotic transports, but for the TCP
            # sockets and SSH channels handled here it always returns a
            # (host, port) tuple. Cast to satisfy Pyright without
            # changing runtime behaviour.
            peer = cast("tuple[str, int]", result.getpeername())

        except OSError as exc:
            self._error = f"Socket has no peer: {exc}"
            return None

        verified = self._probe(result)
        if verified is None:
            return None

        if self.exploit_ctx is not None:
            self.exploit_ctx.success(f"FindShell: shell verified at {peer[0]}:{peer[1]}")
        return _RawConnection(sock=result, addr=peer)

    def stop(self) -> None:
        """No-op — FindShell has no listener to stop."""

    def get_error(self) -> str | None:
        """Return the last connection error, if any."""
        return self._error

    # Internal

    def _probe(self, sock: socket.socket | paramiko.Channel) -> bool | None:
        """Echo-probe the socket or SSH channel to confirm a live shell."""
        try:
            time.sleep(_POST_STAGE_SLEEP)
            sock.settimeout(self.timeout)

            self._flush(sock)

            token = Text.rand_text_alphanumeric(16)
            sock.sendall(f"\necho {token}\n".encode("latin-1"))

            response = b""
            deadline = time.monotonic() + self.timeout
            token_bytes = token.encode("latin-1")
            while time.monotonic() < deadline:
                try:
                    chunk = sock.recv(4096)
                    if chunk:
                        response += chunk
                    if token_bytes in response:
                        break
                except TimeoutError:
                    break

            sock.settimeout(None)

            if token_bytes in response:
                return True

            self._error = "Echo probe did not return expected token — shell not found."
            return None

        except OSError as exc:
            self._error = f"FindShell probe failed: {exc}"
            return None

    @staticmethod
    def _flush(sock: socket.socket | paramiko.Channel) -> None:
        """Drain pending data from the receive buffer."""
        sock.settimeout(1.0)
        with contextlib.suppress(TimeoutError, OSError):
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
