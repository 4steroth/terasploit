from teralibs.terasploit.framework.console.base import BaseConsole
from teralibs.terasploit.framework.console.helpers import to_path
from teralibs.terasploit.framework.services import tables as tbl
from teralibs.terasploit.framework.services.printf import (
    BOLD,
    GREEN,
    RESET,
    error,
    print_line,
    warning,
)


# Each entry is (label, attribute). attribute=None is a sentinel meaning
# "print the resolved module path instead of a TerasploitModule attribute".
META_FIELDS = [
    ("Name", "NAME"),
    ("Module", None),
    ("Platform", "PLATFORM"),
    ("Arch", "ARCH"),
    ("Rank", "RANK"),
    ("Description", "DESCRIPTION"),
    ("Author", "AUTHOR"),
    ("License", "LICENSE"),
    ("References", "REFERENCES"),
]


class ModulesCommands:
    """Handle modules console commands."""

    def __init__(self, console: BaseConsole) -> None:
        """Bind this command group to the shared console."""
        self.console = console

    def cmd_search(self, args):
        """Search the module index and display results in a table."""
        if not args:
            warning("Usage: search <query> [more words...]")
            return

        query = " ".join(args)
        fuzzy = len(args) > 1

        results = self.console.modules.search(query, fuzzy=fuzzy)
        if not results:
            warning(f"No modules matching '{query}'.")
            return

        print_line(f'\nSearch: "{query}"\n')
        tbl.modules_table(results)

        # Guide for users.
        print_line(
            "\n\nInteract with a module by path using",
            f"the command '{GREEN}use <module_path>{RESET}'\n",
        )

    def cmd_info(self, args):
        """Display metadata for the active module or a named one."""
        if args:
            name = args[0].replace("/", ".")
            mod = self.console.modules.load(name)

            if mod is None:
                error(f"Module not found: {args[0]!r}")
                return

            obj = getattr(mod, "TerasploitModule", None)

            if obj is None:
                error(f"Module {args[0]!r} has no TerasploitModule class.")
                return

        else:
            entry = self.console.module_storage.module()

            if entry is None:
                warning("No module loaded.  Run 'info <module>' or load one first.")
                return

            obj = type(entry.module)
            name = entry.name

        self._print_metadata(name, obj)

    def _print_metadata(self, name, obj):
        """Print the metadata table for a resolved module class."""
        print_line()

        for label, attribute in META_FIELDS:
            if attribute is None:
                print_line(f"   {BOLD}{label}:{RESET} {to_path(name)}")
                continue

            value = getattr(obj, attribute, None)
            if value is None:
                continue

            if isinstance(value, (list, tuple)) and value:
                print_line(f"   {BOLD}{label}:{RESET}")
                for item in value:
                    print_line(f"      {item}")

            elif value:
                print_line(f"   {BOLD}{label}:{RESET} {value}")

        print_line()
