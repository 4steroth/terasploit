import shutil
import textwrap

from teralibs.terasploit.framework.options.storage import OPTION_REGISTRY
from teralibs.terasploit.framework.services.printf import print_line
from teralibs.terasploit.framework.services.tables import modules_table
from teralibs.tsf.terax.formatter import FORMATTERS


_FORMAT_ALIASES = frozenset({"py", "rb", "pl", "sh", "ps1"})
_INDENT = "   "
_GAP = "  "
_HEADERS = ("Name", "Current Setting", "Required", "Description")


class TeraxDisplay:
    """Display and listing methods for payload modules, encoders, and formats."""

    def __init__(self, modules):
        """Initialise with a module index for payload and encoder lookups."""
        self._modules = modules

    def list_payloads(self):
        """Print a formatted table of all available payload modules."""
        items = sorted(m for m in self._modules.list_modules() if m.startswith("payload.singles") or m.startswith("payload.stagers"))
        print_line(f"\nPayloads ({len(items)})")
        modules_table(items)
        print_line()

    def list_encoders(self):
        """Print a formatted table of all registered encoder modules."""
        items = sorted(m for m in self._modules.list_modules() if m.startswith("encoder."))
        print_line(f"\nEncoders ({len(items)})")
        modules_table(items)
        print_line()

    def list_all(self):
        """Print payloads, encoders, and formats in sequence."""
        self.list_payloads()
        self.list_encoders()
        self.list_formats()

    @staticmethod
    def list_formats():
        """Print a formatted table of all supported output formats."""
        print_line("\nOutput Formats\n")
        groups = {}

        for name, kind, desc in ((f.name, f.output_type, f.description) for f in FORMATTERS):
            if name not in _FORMAT_ALIASES:
                groups.setdefault(kind, []).append((name, desc))

        for kind in ("binary", "text"):
            label = "Binary" if kind == "binary" else "Transform / Display"
            print_line(label)
            print_line(f"{'-' * len(label)}\n")
            for name, desc in sorted(groups.get(kind, [])):
                print_line(f"    {name:<16} {desc}")
            print_line("\n")

    @staticmethod
    def show_options(payload_obj):
        """Print the option table for payload_obj."""
        wanted = set(getattr(payload_obj, "OPTIONS", None) or [])
        rows = [
            (opt.name, str(opt.default or ""), str(opt.required == 1).lower(), opt.desc)
            for key, opt in OPTION_REGISTRY.items()
            if key.upper() in wanted
        ]
        if not rows:
            return

        widths = [max(len(_HEADERS[i]), *(len(row[i]) for row in rows)) for i in range(3)]
        used = len(_INDENT) + sum(widths) + len(_GAP) * 3
        desc_width = max(shutil.get_terminal_size().columns - used, 30)

        def fmt(name, setting, required, desc):
            cells = (name, setting, required)
            left = _GAP.join(f"{c:<{w}}" for c, w in zip(cells, widths, strict=True))
            return f"{_INDENT}{left}{_GAP}{desc}".rstrip()

        print_line("Basic options:\n")
        print_line(fmt(*_HEADERS))
        print_line(fmt(*("-" * len(h) for h in _HEADERS)))

        for name, setting, required, desc in rows:
            first, *rest = textwrap.wrap(desc, desc_width) or [""]
            print_line(fmt(name, setting, required, first))
            for line in rest:
                print_line(fmt("", "", "", line))

        print_line("\n")
