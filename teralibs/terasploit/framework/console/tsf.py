import argparse
import os
import shutil
import sys

from teralibs.terasploit.framework.console.cli import CLi
from teralibs.terasploit.framework.services.banner import VERSION
from teralibs.terasploit.framework.services.printf import (
    error,
    info,
    print_line,
    set_verbose,
)


class CompactHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """RawDescriptionHelpFormatter with a tighter help-column alignment."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_help_position", 50)

        size = shutil.get_terminal_size(fallback=(80, 24))
        width = size.columns

        # Setting width base on terminal size
        kwargs.setdefault("width", width)

        super().__init__(*args, **kwargs)


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="teraconsole",
        formatter_class=CompactHelpFormatter,
        color=False,
    )

    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable verbose/debug output (shows [~] messages)",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Print version and exit",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Skip the banner",
    )
    parser.add_argument(
        "-r",
        "--resource",
        metavar="FILE",
        help="Execute commands from a resource (.rc) script file",
    )
    parser.add_argument(
        "-m",
        "--module",
        metavar="MODULE",
        help="Preload a module before dropping into the REPL",
    )
    parser.add_argument(
        "-x",
        "--execute",
        metavar="CMDs",
        help='Execute semicolon-separated commands, then drop to REPL (e.g. "use x; set Y z")',
    )

    return parser


# Resource script runner
def _run_resource(console, filepath):
    """Execute each non-blank, non-comment line of *filepath* as a console command."""
    if not os.path.isfile(filepath):
        error(f"Resource file not found: {filepath!r}")
        return

    info(f"Running resource script: {filepath}")
    with open(filepath, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            try:
                cmd, args = console.parse_line(line)
                if cmd:
                    console.dispatch(cmd, args)

            except RuntimeError as exc:
                error(f"[rc:{lineno}] {exc}")


# Inline command string runner
def _run_inline(console, command_string):
    """Execute a semicolon-separated list of commands immediately."""
    for raw in command_string.split(";"):
        line = raw.strip()
        if not line:
            continue

        try:
            cmd, args = console.parse_line(line)
            if cmd:
                console.dispatch(cmd, args)

        except RuntimeError as exc:
            error(f"[inline] {exc}")


# Entry point
def main():
    """The main entry point of terasploit framework"""
    parser = _build_parser()
    opts = parser.parse_args()

    if opts.version:
        print_line(f"Terasploit Framework {VERSION}")
        sys.exit(0)

    if opts.debug:
        set_verbose(True)

    console = CLi(verbose=opts.debug, silent_banner=opts.quiet)

    if opts.module:
        console.dispatch("use", [opts.module])

    if opts.execute:
        _run_inline(console, opts.execute)

    if opts.resource:
        _run_resource(console, opts.resource)

    # Drop into the interactive REPL.
    console.start()
