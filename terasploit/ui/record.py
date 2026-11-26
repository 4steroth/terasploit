import contextlib
import datetime
import importlib
import os
import re
import sys
import threading
from collections.abc import Iterable
from typing import Any, TextIO


# CSI sequences and OSC sequences (BEL or ST terminated).
ansi_pattern = re.compile(r"\033(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")

# An escape sequence cut off at the end of a write; completed by the next one.
partial_ansi_pattern = re.compile(r"\033(?:\[[0-?]*[ -/]*|\][^\x07\x1b]*\x1b?)?\Z")
readline_pattern = re.compile(r"[\x01\x02]")

# Bound on held-back text so a stray ESC can never swallow later output.
MAX_PENDING_ESCAPE = 256


class RecordingStream:
    """Forward text to an output stream while recording it."""

    def __init__(self, stream: TextIO, rec: TranscriptRecorder) -> None:
        """Initialize the recording stream wrapper."""
        self.stream = stream
        self.recorder = rec

    def write(self, text: str) -> int:
        """Write text to the original stream and transcript."""
        with self.recorder.lock:
            result = self.stream.write(text)
            self.recorder.write(text)
            return result

    def writelines(self, lines: Iterable[str]) -> None:
        """Write each line through the recording path."""
        for line in lines:
            self.write(line)

    def flush(self) -> None:
        """Flush the original output stream."""
        self.stream.flush()

    def __getattr__(self, name: str) -> Any:
        """Delegate missing attributes to the original stream."""
        return getattr(self.stream, name)


class TranscriptRecorder:
    """Record console output and operator input into one transcript."""

    def __init__(self) -> None:
        """Initialize transcript state and output stream references."""
        self.file: TextIO | None = None
        self.path = None
        self.lock = threading.RLock()
        self.original_stdout = None
        self.original_stderr = None
        self.printf_module = None
        self.original_printf_file = None
        self.streams = {}
        self.pending_escape = ""

    @property
    def active(self) -> bool:
        """Return whether transcript recording is active."""
        return self.file is not None

    def start(self, filename: str | None = None) -> str:
        """Start recording console output and operator input."""
        with self.lock:
            if self.active:
                raise RuntimeError("Recording is already active.")

            if filename is None:
                timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                filename = f"terasploit-{timestamp}.log"

            path = os.path.abspath(os.path.expanduser(filename))
            file = open(  # noqa: SIM115
                path, "w", encoding="utf-8", errors="replace", buffering=1
            )

            try:
                self.original_stdout = sys.stdout
                self.original_stderr = sys.stderr
                self.printf_module = importlib.import_module("terasploit.ui.printf")
                self.original_printf_file = self.printf_module.State.file

                for stream in (
                    self.original_stdout,
                    self.original_stderr,
                    self.original_printf_file,
                ):
                    if stream is not None and id(stream) not in self.streams:
                        self.streams[id(stream)] = (
                            stream,
                            RecordingStream(stream, self),
                        )

                self.file = file
                self.path = path
                self.pending_escape = ""

                sys.stdout = self._wrapper_for(self.original_stdout)
                sys.stderr = self._wrapper_for(self.original_stderr)
                self.printf_module.State.file = self._wrapper_for(self.original_printf_file)

            except BaseException:
                try:
                    self._restore_streams()
                finally:
                    try:
                        file.close()
                    finally:
                        self._reset_state()
                raise

            return path

    def stop(self) -> str | None:
        """Stop recording and restore the original output streams."""
        with self.lock:
            file = self.file
            if file is None:
                return None

            path = self.path

            try:
                self._restore_streams()
                file.flush()
            finally:
                try:
                    file.close()
                finally:
                    self._reset_state()

            return path

    def write_input(self, text: str) -> None:
        """Append operator input to the active transcript."""
        with self.lock:
            if self.active:
                self.write(text.rstrip("\r\n") + "\n")

    def write(self, text: str) -> None:
        """Write sanitized text to the active transcript."""
        with self.lock:
            file = self.file
            if file is None:
                return

            try:
                file.write(self._sanitize(text))
                file.flush()
            except (OSError, ValueError) as exc:
                self._abort_recording(exc)

    def _wrapper_for(self, stream):
        """Return the recording wrapper for a stream, or the stream itself."""
        entry = self.streams.get(id(stream))
        return entry[1] if entry is not None else stream

    def _restore_streams(self) -> None:
        """Reinstall original streams where our wrappers are still in place."""
        if self.original_stdout is not None and sys.stdout is self._wrapper_for(self.original_stdout):
            sys.stdout = self.original_stdout

        if self.original_stderr is not None and sys.stderr is self._wrapper_for(self.original_stderr):
            sys.stderr = self.original_stderr

        if self.printf_module is not None and self.original_printf_file is not None:
            wrapper = self._wrapper_for(self.original_printf_file)
            if self.printf_module.State.file is wrapper:
                self.printf_module.State.file = self.original_printf_file

    def _reset_state(self) -> None:
        """Clear all recording state."""
        self.file = None
        self.path = None
        self.original_stdout = None
        self.original_stderr = None
        self.printf_module = None
        self.original_printf_file = None
        self.streams.clear()
        self.pending_escape = ""

    def _abort_recording(self, error: Exception) -> None:
        """Stop recording after a transcript failure and warn once."""
        with contextlib.suppress(Exception):
            self.stop()
        sys.stderr.write(f"Transcript recording stopped: {error}\n")

    def _sanitize(self, text: str) -> str:
        """Strip readline markers and ANSI sequences, even when split across writes."""
        text = self.pending_escape + readline_pattern.sub("", text)
        self.pending_escape = ""
        text = ansi_pattern.sub("", text)

        partial = partial_ansi_pattern.search(text)
        if partial and len(text) - partial.start() <= MAX_PENDING_ESCAPE:
            self.pending_escape = text[partial.start() :]
            text = text[: partial.start()]

        return text


recorder = TranscriptRecorder()
