from collections.abc import Sequence

from terasploit.console.helpers import to_path
from terasploit.ui import tables as tbl
from terasploit.ui.printf import (
    BOLD,
    RESET,
    error,
    print_line,
    warning,
)


class ModulesCommands:
    """Handle modules console commands."""

    # Each entry is (label, attribute). attribute=None is a sentinel meaning
    # "print the resolved module path instead of a TerasploitModule attribute".
    META_FIELDS: Sequence = [
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

    def __init__(self, console) -> None:
        self.console = console

    def cmd_search(self, args):
        """Search the module index and display results in a table."""
        if not args:
            warning("Usage: search <query> [more words...]")
            return

        query = " ".join(args)
        results = self.console.modules.search(query, fuzzy=len(args) > 1)
        if not results:
            warning(f"No modules matching '{query}'.")
            return

        print_line(f'\nSearch: "{query}"\n')
        tbl.modules_table(results)
        print_line("\n")

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

        for label, attribute in self.META_FIELDS:
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
