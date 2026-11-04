import dataclasses
import datetime
import sys


# ANSI escape codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GRAY = "\033[90m"
WHITE = "\033[37m"


@dataclasses.dataclass
class State:
    """Holds the state of the console print function."""

    # When True, debug() calls produce output; otherwise they are no-ops.
    verbosity: bool = False

    # When True, every log line is prefixed with the current wall-clock time.
    timestamp: bool = False


# State mutators


def set_verbose(enabled=True):
    """Toggle debug output on or off."""
    State.verbosity = enabled


def get_verbose():
    """Return True when debug output is currently enabled."""
    return State.verbosity


def set_timestamp(enabled=True):
    """Toggle wall-clock timestamp prefixes on log lines."""
    State.timestamp = enabled


# Internal emission helpers


def _emit_write(message):
    """Write one formatted log line to stdout and flush immediately."""
    sys.stdout.write(message)
    sys.stdout.flush()


def _emit(symbol, color, message):
    """Format and write one log line with the given *symbol* and *color*."""
    if State.timestamp is True:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        timestamp = f"[{CYAN}{now}{RESET}]"
        _emit_write(f"{timestamp} [{color}{symbol}{RESET}] {message}\n")

    if State.timestamp is False:
        _emit_write(f"{color}{symbol}{RESET} {message}\n")


# Public log functions


def info(message):
    """Emit a [*] informational message (blue)."""
    _emit("[*]" if not State.timestamp else "INFO", BOLD + BLUE, message)


def success(message):
    """Emit a [+] success message (green)."""
    _emit("[+]" if not State.timestamp else "SUCCESS", BOLD + GREEN, message)


def warning(message):
    """Emit a [!] warning message (yellow)."""
    _emit("[!]" if not State.timestamp else "WARNING", BOLD + YELLOW, message)


def error(message):
    """Emit a [-] error message (red)."""
    _emit("[-]" if not State.timestamp else "ERROR", BOLD + RED, message)


def debug(message):
    """Emit a [~] debug message (gray)."""
    if State.verbosity:
        _emit("[~]" if not State.timestamp else "DEBUG", CYAN, message)


def print_line(
    *args,
    sep=" ",
    end="\n",
    file=sys.stdout,
    flush=False,
):
    """
    Write a plain line to stdout with no symbol prefix.
    Used for table output, banners, and any prose that should not carry
    a log-level symbol.
    """
    file.write((sep if sep is not None else " ").join(str(a) for a in args) + (end if end is not None else "\n"))
    if flush:
        file.flush()
