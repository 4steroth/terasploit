import subprocess

from teralibs.terasploit.framework.console.base import BaseConsole
from teralibs.terasploit.framework.console.help import help_sections
from teralibs.terasploit.framework.encoder.factory import EncoderFactory
from teralibs.terasploit.framework.services.banner import display_banner
from teralibs.terasploit.framework.services.printf import (
    error,
    info,
    print_line,
    success,
    warning,
)
from teralibs.tsf.utils.exception import ShellExecError


COMMAND_COLUMN_WIDTH = 30


class CoreCommands:
    """Handle core console commands."""

    def __init__(self, console: BaseConsole) -> None:
        """Bind this command group to the shared console."""
        self.console = console

    def cmd_banner(self, _: list[str]) -> None:
        """Display the terasploit framework banner."""
        display_banner(self.console.modules.list_modules())

    def cmd_help(self, _: list[str]) -> None:
        """Display a grouped command reference table."""
        width = COMMAND_COLUMN_WIDTH

        print_line()

        for section_name, entries in help_sections:
            print_line(f"{section_name} commands\n")
            print_line(f"   {'Command':<{width}} Description")
            print_line(f"   {'-------':<{width}} -----------")

            for command, description in entries:
                print_line(f"   {command:<{width}}  {description}")

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
            result = subprocess.run(command_string, shell=True, check=False)

        except ShellExecError as exc:
            error(f"Shell execution failed: {exc}")
            return

        if result.returncode != 0:
            warning(f"Command exited with status {result.returncode}.")

    def cmd_reload(self, _: list[str]) -> None:
        """Force-rescan the module index and reset the encoder registry."""
        self.console.modules.refresh(force=True)
        EncoderFactory.reset()

        count = len(self.console.modules)
        success(f"Module index refreshed - {count} module(s) indexed.")
