import shlex

from terasploit.console.base import BaseConsole
from terasploit.console.commands.core import CoreCommands
from terasploit.console.commands.execution import ExecutionCommands
from terasploit.console.commands.modules import ModulesCommands
from terasploit.console.commands.sessions import SessionsCommands
from terasploit.console.display import ConsoleDisplay
from terasploit.console.helpers import to_path
from terasploit.console.loader import ConsoleLoader
from terasploit.ui import tables as tbl
from terasploit.ui.printf import (
    BOLD,
    RED,
    RESET,
    error,
    print_line,
    warning,
)


class CLi(BaseConsole):
    """Provide the interactive Terasploit command-line interface."""

    def __init__(self, **kwargs) -> None:
        """Initialize the console and register its module index."""
        super().__init__(**kwargs)
        self.core_commands = CoreCommands(self)
        self.module_commands = ModulesCommands(self)
        self.execution_commands = ExecutionCommands(self)
        self.session_commands = SessionsCommands(self)
        self.loaders = ConsoleLoader(self)
        self.display = ConsoleDisplay(self)
        tbl.set_module_index(self.modules)

    def dispatch(self, command: str, args: list[str]) -> None:
        """Resolve command aliases and invoke the owning component."""
        if command in {"exit", "quit", "q", "close", "terminate"}:
            self.shutdown()
            return

        if command in {"run", "exploit", "execute"}:
            command = "run"

        command = {"?": "help", "session": "sessions", "i": "interact", "k": "kill"}.get(command, command)

        if command == "show":
            self.display.cmd_show(args)
            return

        if command in {"use", "back", "set", "unset"}:
            getattr(self.loaders, f"cmd_{command}")(args)
            return

        components = (self.core_commands, self.module_commands, self.execution_commands, self.session_commands)
        for component in components:
            handler = getattr(component, f"cmd_{command}", None)
            if handler is not None:
                handler(args)
                return

        warning(f"Unknown command: '{command}'.  Type 'help' for a list.")

    def flush_job_output(self) -> None:
        """Drain pending background-job output through the session component."""
        self.session_commands.flush_job_output()

    def _user_prompt(self):
        """Build the context-sensitive prompt string."""
        label = self.datastore["PROMPT"]
        char = self.datastore["PROMPT_CHAR"]

        entry = self.module_storage.module()
        if entry is None:
            return f"\001\033[4m\002{label}\001{RESET}\002 {char} "

        display = to_path(entry.name).split("/")[-1]
        category = to_path(entry.name).split("/")[0]

        return f"\001\033[4m\002{label}\001{RESET}\002::{category}(\001{BOLD}\002\001{RED}\002{display}\001{RESET}\002) {char} "

    def parse_line(self, line):
        """Returns a (command, args) pair."""
        stripped = line.strip()

        if not stripped:
            return "", []

        try:
            tokens = shlex.split(stripped)

        except ValueError as exc:
            raise RuntimeError(f"Parse error: {exc}") from exc

        return tokens[0].lower(), tokens[1:]

    def start(self):
        """Enter the interactive read-eval loop."""
        while self.console_toggle:
            if self.thread_handler.output_bus.pending() > 0:
                self.session_commands.flush_job_output()

            try:
                raw = input(self._user_prompt()).strip()

            except KeyboardInterrupt:
                print_line()
                warning("Interrupt received.  Type 'exit' to quit.")
                continue

            except EOFError:
                print_line()
                error("EOF received - shutting down.")
                self.shutdown()
                break

            try:
                command, args = self.parse_line(raw)

            except RuntimeError as exc:
                error(str(exc))
                continue

            if not command:
                continue

            self.dispatch(command, args)
