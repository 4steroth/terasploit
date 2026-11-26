import dataclasses
import datetime
import re
import sys
from typing import IO


# ANSI escape codes
RESET = "\033[0m"
BOLD = "\033[0;1m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
BLUE = "\033[0;34m"
CYAN = "\033[0;36m"
GRAY = "\033[0;90m"
WHITE = "\033[0;37m"

ANSI_PATTERN = re.compile(r"\033\[[0-?]*[ -/]*[@-~]")


@dataclasses.dataclass
class State:
    """Holds the state of the console print function."""

    # When True, debug() calls produce output; otherwise they are no-ops.
    verbosity: bool = False

    # When True, every log line is prefixed with the current wall-clock time.
    timestamp: bool = False

    # File to write the output
    file: IO = sys.stdout


def set_verbose(enabled=True):
    """Toggle debug output on or off."""
    State.verbosity = enabled


def get_verbose():
    """Return True when debug output is currently enabled."""
    return State.verbosity


def set_timestamp(enabled=True):
    """Toggle wall-clock timestamp prefixes on log lines."""
    State.timestamp = enabled


def write(text, flush=False):
    """Write output to the configured stream and optionally to the loot file."""
    State.file.write(text)
    if flush:
        State.file.flush()


def print_line(*args, sep=" ", end="\n", flush=False):
    """Write a plain line to stdout with no symbol prefix."""
    text = (sep if sep is not None else " ").join(map(str, args))
    write(text + (end if end is not None else "\n"), flush=flush)


def log(symbol, color, *message, sep=" ", end="\n", flush=False):
    """Format and write one log line with the given symbol and color."""
    prefix = f"{color}{symbol}{RESET} "

    if State.timestamp:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        prefix = f"[{CYAN}{now}{RESET}] {prefix}"

    write(
        prefix + (sep if sep is not None else " ").join(map(str, message)) + (end if end is not None else "\n"),
        flush=flush,
    )


def info(*message, sep=" ", end="\n", flush=False):
    """Emit an informational message."""
    log("[*]", BOLD + BLUE, *message, sep=sep, end=end, flush=flush)


def success(*message, sep=" ", end="\n", flush=False):
    """Emit a success message."""
    log("[+]", BOLD + GREEN, *message, sep=sep, end=end, flush=flush)


def warning(*message, sep=" ", end="\n", flush=False):
    """Emit a warning message."""
    log("[!]", BOLD + YELLOW, *message, sep=sep, end=end, flush=flush)


def error(*message, sep=" ", end="\n", flush=False):
    """Emit an error message."""
    log("[-]", BOLD + RED, *message, sep=sep, end=end, flush=flush)


def debug(*message, sep=" ", end="\n", flush=False):
    """Emit a debug message when verbosity is enabled."""
    if State.verbosity:
        log("[~]", CYAN, *message, sep=sep, end=end, flush=flush)
