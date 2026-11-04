import contextlib
import dataclasses
import queue
import re
import socket
import threading
from dataclasses import field
from typing import Any


LISTENER_ACCEPT_TIMEOUT: float = 100.0
SOCKET_BACKLOG: int = 1
HANDLER_TYPE: str = "reverse"


def _looks_like_ip(value: str) -> bool:
    return bool(re.compile(r"^(\d{1,3}\.){3}\d{1,3}$").match(value or ""))


@dataclasses.dataclass
class _RawConnection:
    sock: Any
    addr: tuple[str, int]


@dataclasses.dataclass
class _ListenerConfig:
    lhost: str
    lport: int
    timeout: float


@dataclasses.dataclass
class _ConnectionResult:
    sock: Any = None
    addr: tuple[str, int] | None = None
    error: str | None = None
    event: Any = field(default_factory=threading.Event)


class ReverseTcpHandler:
    """
    Opens a listening socket on LHOST:LPORT and waits for the target to
    connect back after being exploited.

    wait(result) is the single post-exploit entry point called by driver.py.
    It blocks until a connection arrives, the timeout fires, or the job is
    killed.  result is the return value of module.run() — ignored here since
    the reverse handler manages its own listener.
    """

    HANDLER_TYPE = HANDLER_TYPE

    def __init__(
        self,
        lhost: str,
        lport: int,
        timeout: float = LISTENER_ACCEPT_TIMEOUT,
        threaded: bool = False,
        ctx: Any = None,
        exploit_ctx: Any = None,
    ) -> None:
        self._config = _ListenerConfig(lhost=lhost, lport=int(lport), timeout=timeout)
        self._result = _ConnectionResult()
        self._server_sock = None
        self._thread = None
        self._threaded = threaded
        self.ctx = ctx
        self.exploit_ctx = exploit_ctx
        self._conn_queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()

    # Factory

    @classmethod
    def from_datastore(
        cls,
        datastore,
        timeout: float = LISTENER_ACCEPT_TIMEOUT,
        opts: dict | None = None,
    ) -> ReverseTcpHandler:
        """
        Construct from framework datastore values.

        Bind address resolution order:
        1. opts['bind_address'] (pre-resolved by driver._build_listener)
        2. opts['comm'] when it looks like an IP
        3. LHOST datastore value
        4. 0.0.0.0 fallback
        """
        opts = opts or {}

        bind_addr = opts.get("bind_address") or ""
        if not bind_addr:
            comm = opts.get("comm") or ""
            if comm and _looks_like_ip(comm):
                bind_addr = comm
        if not bind_addr:
            bind_addr = datastore.get("LHOST") or "0.0.0.0"

        raw_port = opts.get("bind_port") or datastore.get("LPORT")
        if not raw_port:
            raise ValueError("LPORT must be set for reverse_tcp handler.")

        return cls(
            lhost=bind_addr,
            lport=int(raw_port),
            timeout=timeout,
            threaded=bool(opts.get("threaded", False)),
            ctx=opts.get("ctx"),
            exploit_ctx=opts.get("exploit_ctx"),
        )

    # Driver contract

    def start(self) -> None:
        """Bind and start the accept thread."""
        self._stop_event.clear()
        backlog = 5 if self._threaded else SOCKET_BACKLOG
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.settimeout(self._config.timeout)
        self._server_sock.bind((self._config.lhost, self._config.lport))
        self._server_sock.listen(backlog)

        target = self._accept_loop_threaded if self._threaded else self._accept_loop
        self._thread = threading.Thread(
            target=target,
            daemon=True,
            name="reverse-tcp-handler",
        )
        self._thread.start()

    def wait(self, _result: Any = None) -> _RawConnection | None:
        """
        Wait for an incoming connection and return a _RawConnection.

        result is the return value of module.run() — ignored, present only
        for API uniformity with bind and find handlers.

        Polls in 0.5 s increments so the job kill signal is honoured
        without a full-timeout block.
        """
        bind_addr = self._config.lhost
        bind_port = self._config.lport

        if self.exploit_ctx is not None:
            self.exploit_ctx.info(f"Waiting for connection on {bind_addr}:{bind_port}...")

        while True:
            if self.ctx is not None and self.ctx.is_killed():
                return None

            done = self._wait_for_connection(poll=0.5)
            if done is not None:
                sock, addr = done
                if addr is None or not isinstance(addr, tuple):
                    if self.exploit_ctx is not None:
                        self.exploit_ctx.error("Received an invalid or missing connection address.")
                    continue
                return _RawConnection(sock=sock, addr=addr)

            if self._result.error:
                return None

            if self._server_sock is None:
                return None

    def stop(self) -> None:
        """Shut down the listening socket."""
        self._stop_event.set()
        if self._threaded:
            with contextlib.suppress(Exception):
                self._conn_queue.put_nowait(None)
        if self._server_sock is not None:
            with contextlib.suppress(OSError):
                self._server_sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                self._server_sock.close()
            self._server_sock = None

    def get_error(self) -> str | None:
        """Return the last connection error, if any."""
        return self._result.error

    # Internal

    def _wait_for_connection(self, poll: float | None = None) -> tuple | None:
        """Low-level connection retrieval used by wait()."""
        if self._threaded:
            try:
                item = self._conn_queue.get(timeout=poll)
                return item
            except queue.Empty:
                return None

        if poll is None:
            self._result.event.wait()
        elif not self._result.event.wait(timeout=poll):
            return None

        if self._result.sock is not None:
            return self._result.sock, self._result.addr
        return None

    def _accept_loop(self) -> None:
        """Single-connection accept loop for non-threaded mode."""
        if self._server_sock is None:
            self._result.error = "Server socket does not exist."
            self._result.event.set()
            return
        try:
            sock, addr = self._server_sock.accept()
            sock.settimeout(None)
            self._result.sock = sock
            self._result.addr = addr
        except TimeoutError:
            self._result.error = "Listener timed out waiting for connection."
        except OSError as exc:
            self._result.error = str(exc)
        finally:
            self._result.event.set()

    def _accept_loop_threaded(self) -> None:
        """Threaded accept loop for multi-connection mode."""
        while not self._stop_event.is_set():
            try:
                if self._server_sock is None:
                    break
                self._server_sock.settimeout(1.0)
                try:
                    sock, addr = self._server_sock.accept()
                except TimeoutError:
                    continue
                sock.settimeout(None)
                self._conn_queue.put((sock, addr))
            except OSError as exc:
                if not self._stop_event.is_set():
                    self._result.error = str(exc)
                break
