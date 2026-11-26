import subprocess
import sys

from terasploit.console.help import SECTIONS
from terasploit.encoder.factory import EncoderFactory
from terasploit.ui import tables as tbl
from terasploit.ui.banner import display_banner
from terasploit.ui.printf import (
    error,
    info,
    print_line,
    success,
    warning,
)
from terasploit.ui.record import recorder
from terasploit.utils.exception import ShellExecError


class CoreCommands:
    """Handle core console commands."""

    def __init__(self, console) -> None:
        self.console = console

    def cmd_banner(self, _: list[str]) -> None:
        """Display the terasploit framework banner."""
        display_banner(self.console.modules.list_modules())

    def cmd_help(self, _: list[str]) -> None:
        """Display a grouped command reference table."""
        schema = tbl.TableSchema(
            headers=("Command", "Description"),
            min_widths=[36, 20],
            wrap_widths=[36, 60],
            padding=3,
        )
        print_line()

        for section_name, entries in SECTIONS:
            print_line(f"{section_name} commands\n")
            tbl.TableRenderer(schema).render(entries)
            print_line("\n")

    def cmd_clear(self, _: list[str]) -> None:
        """Clear the terminal screen."""
        subprocess.run(["clear"], shell=True, check=False)

    def cmd_exec(self, args: list[str]) -> None:
        """Execute a system shell command and stream its output to the console."""
        if not args:
            warning("Usage: exec <command>  (example: exec whoami)")
            return

        command_string = " ".join(args)
        info(f"Executing: {command_string}")

        try:
            process = subprocess.Popen(
                command_string,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
        except OSError as exc:
            error(f"Shell execution failed: {exc}")
            return
        try:
            if process.stdout is None:
                raise ShellExecError("Could not display output, process stdout is None.")
            with process.stdout:
                for line in process.stdout:
                    sys.stdout.write(line)
                    sys.stdout.flush()

            returncode = process.wait()
        except ShellExecError as exc:
            process.kill()
            process.wait()
            error(f"Shell execution failed: {exc}")
            return
        except KeyboardInterrupt:
            process.terminate()
            process.wait()
            warning("Command interrupted.")
            return

        if returncode != 0:
            warning(f"Command exited with code {returncode}")

    def cmd_record(self, args: list[str]) -> None:
        """Start, stop, or inspect console transcript recording."""
        if not args:
            if recorder.active:
                info(f"Recording to: {recorder.path}")
            else:
                info("No active recording.")
            return

        action = args[0].lower()
        if action == "start":
            if len(args) > 2:
                warning("Usage: record start [file]")
                return
            try:
                path = recorder.start(args[1] if len(args) == 2 else None)
            except (OSError, RuntimeError, ValueError) as exc:
                error(f"Unable to start recording: {exc}")
                return

            prompt = getattr(self.console, "_user_prompt", lambda: "")()
            command = "record start" + (f" {args[1]}" if len(args) == 2 else "")
            recorder.write_input(f"{prompt}{command}")
            success(f"Recording started: {path}")
        elif action == "stop":
            if not recorder.active:
                warning("No active recording.")
                return

            path = recorder.path
            success(f"Recording stopped: {path}")
            recorder.stop()
        elif action == "status":
            if recorder.active:
                info(f"Recording to: {recorder.path}")
            else:
                info("No active recording.")
        else:
            warning("Usage: record <start [file] | stop | status>")

    def cmd_reload(self, _: list[str]) -> None:
        """Force-rescan the module index and reset the encoder registry."""
        self.console.modules.refresh(force=True)
        EncoderFactory.reset()

        count = len(self.console.modules)
        success(f"Module index refreshed - {count} module(s) indexed.")
