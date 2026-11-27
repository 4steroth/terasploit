from collections.abc import Mapping

from terasploit.console.helpers import (
    category_of,
    filter_compatible,
    target_details,
    to_path,
)
from terasploit.ui import tables as tbl
from terasploit.ui.printf import (
    info,
    print_line,
    warning,
)


class ConsoleDisplay:
    """Render module, option, advanced, and evasion information."""

    CATEGORY_LABELS: Mapping = {
        "exploit": "Exploit",
        "auxiliary": "Auxiliary",
        "payload": "Payload",
        "encoder": "Encoder",
        "post": "Post",
        "evasion": "Evasion",
    }

    def __init__(self, console) -> None:
        self.console = console

    def cmd_show(self, args):
        """Dispatch show sub-commands to their respective display methods."""
        if not args:
            warning("Usage: show <target> - options, advanced, targets, modes, all, exploits, payloads, auxiliary, encoders, post")
            return

        sub = args[0].lower()
        sub_dispatch = {
            "options": self.show_options,
            "advanced": self.show_advanced,
            "evasion": self.show_evasion,
            "targets": self.show_targets,
            "modes": self.show_auxiliary_modes,
            "all": self.show_category,
            "modules": self.show_category,
            "exploits": lambda: self.show_category("exploit"),
            "payloads": lambda: self.show_category("payload"),
            "auxiliary": lambda: self.show_category("auxiliary"),
            "encoders": lambda: self.show_category("encoder"),
            "post": lambda: self.show_category("post"),
        }

        handler = sub_dispatch.get(sub)
        if handler is None:
            warning(f"Unknown show target '{sub}'.  Try: options, advanced, targets, modes, all, exploits, payloads, auxiliary, encoders, post.")
            return
        if sub in ("modules", "exploits", "auxiliary", "payloads", "encoders", "post", "all"):
            print_line(f'\nShow: "{sub}"\n')

        handler()
        print_line("\n")

    def show_options(self):
        """Display module, payload, encoder options, and targets."""
        entry = self.console.module_storage.module()
        if entry is None:
            return self.show_framework_options()

        category = category_of(entry.name)
        label = self.CATEGORY_LABELS.get(category, category.capitalize())
        self._show_module_options(entry, category, label)

        pay_entry = self.console.module_storage.payload()
        self._show_payload_options(entry, pay_entry)

        enc_entry = self.console.module_storage.encoder()
        self._show_encoder_options(pay_entry, enc_entry)

        self._show_targets(entry)
        return None

    def _show_module_options(self, entry, category, label):
        """Display the active module's options."""
        if category not in ("exploit", "auxiliary", "payload", "post", "evasion"):
            return

        definitions = self.console.datastore.definitions("module")
        has_options = bool(definitions) if category == "post" else entry.module.OPTIONS
        if has_options and definitions:
            tbl.options_table(
                f"{label} options ({to_path(entry.name)})",
                definitions,
                self.console.datastore.all_values("module"),
            )

    def _show_payload_options(self, entry, pay_entry):
        """Display payload options or the module's empty-options message."""
        definitions = self.console.datastore.definitions("payload")
        if pay_entry is None:
            if not self.console.datastore.definitions("module"):
                label = self.CATEGORY_LABELS.get(
                    category_of(entry.name),
                    category_of(entry.name).capitalize(),
                )
                print_line(f"\n{label} options ({to_path(entry.name)}):\n")
                print_line("   (no options available for this module)\n")
            return
        if category_of(entry.name) == "exploit" and entry.module.OPTIONS:
            # Add new line for better table spacing
            print_line()
        if definitions:
            tbl.options_table(
                f"Payload options ({to_path(pay_entry.name)})",
                definitions,
                self.console.datastore.all_values("payload"),
            )

    def _show_encoder_options(self, pay_entry, enc_entry):
        """Display encoder options."""
        if enc_entry is None:
            return
        if pay_entry is not None:
            print_line()

        definitions = self.console.datastore.definitions("encoder")
        if definitions:
            tbl.options_table(
                f"Encoder options ({to_path(enc_entry.name)})",
                definitions,
                self.console.datastore.all_values("encoder"),
            )

    def _show_targets(self, entry):
        """Display the currently selected module target."""
        targets = getattr(entry.module, "TARGET", None)
        if not targets:
            return

        current_target = self.console.datastore["TARGET"]
        for target in targets:
            try:
                target_id, target_name, _ = target_details(target)
            except ValueError:
                continue
            if current_target == target_name:
                print_line()
                tbl.targets_table(((target_id, target_name),), title="Target")
                return

    def show_advanced(self):
        """Display advanced options for the active module and its payload."""
        entry = self.console.module_storage.module()
        if entry is None:
            warning("No module loaded.")
            return

        category = category_of(entry.name)
        if category == "exploit":
            self.show_module_advanced(entry)
            self.show_payload_advanced()
            self.show_encoder_summary()
            return
        if category == "payload":
            self.show_payload_advanced()
            self.show_encoder_summary()
            return

        self.show_module_advanced(entry)

    def _render_scoped_options(self, scope, title, no_options_message=None):
        """Render a datastore scope's options table, or a fallback message if it's empty."""
        defs = self.console.datastore.definitions(scope)
        vals = self.console.datastore.all_values(scope)
        if defs:
            tbl.options_table(title, defs, vals)
        elif no_options_message:
            info(no_options_message)

    def show_module_advanced(self, entry):
        """Render the advanced options table for the active module."""
        name = entry.name
        category = category_of(name)

        label = self.CATEGORY_LABELS.get(category, category.capitalize())
        self._render_scoped_options(
            "module_advanced",
            f"{label} advanced options ({to_path(name)})",
            no_options_message=f"No advanced options for {to_path(name)}.",
        )

    def show_payload_advanced(self):
        """Render the advanced options table for the active payload, if any."""
        pay_entry = self.console.module_storage.payload()
        if pay_entry is None:
            return

        self._render_scoped_options(
            "payload_advanced",
            f"Payload advanced options ({to_path(pay_entry.name)})",
        )

    def show_encoder_summary(self):
        """Print a one-line summary of the active encoder, if any."""
        enc_entry = self.console.module_storage.encoder()
        if enc_entry is None:
            return

        # Getting encoder metadata
        enc_obj = enc_entry.module
        rank = enc_obj.RANK
        rank_lbl = getattr(rank, "label", lambda: str(rank))()
        arch_str = ", ".join(enc_obj.ARCH or []) or "generic"
        description = getattr(enc_obj, "DESCRIPTION", "")

        print_line(f"\nActive encoder: {to_path(enc_entry.name)} [rank={rank_lbl}, arch={arch_str}]")
        print_line(f"Description   : {description[:90]}")

    def show_evasion(self):
        """Display evasion options for the active module and its payload."""
        entry = self.console.module_storage.module()
        if entry is None:
            return

        category = category_of(entry.name)
        if category == "exploit":
            self.show_module_evasion(entry)
            self.show_payload_evasion()
            return
        if category == "payload":
            self.show_payload_evasion()
            return

        self.show_module_evasion(entry)

    def show_module_evasion(self, entry):
        """Render the evasion options table for the active module."""
        name = entry.name
        category = category_of(name)

        label = self.CATEGORY_LABELS.get(category, category.capitalize())
        self._render_scoped_options(
            "module_evasion",
            f"{label} evasion options ({to_path(name)})",
            no_options_message=f"No evasion options for {to_path(name)}.",
        )

    def show_payload_evasion(self):
        """Render the evasion options table for the active payload, if any."""
        pay_entry = self.console.module_storage.payload()
        if pay_entry is None:
            return

        self._render_scoped_options(
            "payload_evasion",
            f"Payload evasion options ({to_path(pay_entry.name)})",
        )

    def show_framework_options(self):
        """Display the framework core options stored in the framework scope."""
        fw_defs = self.console.datastore.definitions("framework")
        fw_vals = self.console.datastore.all_values("framework")
        if fw_defs:
            tbl.options_table("Framework core options", fw_defs, fw_vals)
            return

        print_line()
        info("No framework options are registered.")
        print_line()

    def _show_module_settings(self, attr, title, module_name):
        """Display module settings like exploit targets or auxiliary modes."""
        entry = self.console.module_storage.module()
        if entry is None:
            warning(f"No module loaded. Use '{module_name}' module first.")
            return

        settings = getattr(entry.module, attr, None)
        if not settings:
            warning(f"This {module_name} module does not declare any {title.lower()}")
            return
        if attr == "TARGET":
            normalized = []
            for target in settings:
                try:
                    target_id, target_name, _ = target_details(target)
                except ValueError:
                    continue
                normalized.append((target_id, target_name))
            settings = normalized

        tbl.targets_table(settings, title=title)

    def show_auxiliary_modes(self):
        """Display the auxiliary modes."""
        self._show_module_settings(
            "AUXILIARY_MODE",
            "Auxiliary modes",
            "auxiliary",
        )

    def show_targets(self):
        """Display the targets declared by the exploit module."""
        self._show_module_settings(
            "TARGET",
            "Targets",
            "exploit",
        )

    def show_category(self, category=None):
        """Display a modules table filtered by category."""
        all_modules = self.console.modules.list_modules()
        filtered = [m for m in all_modules if category_of(m) == category] if category is not None else all_modules

        entry = self.console.module_storage.module()
        if entry is not None and category in ("payload", "encoder"):
            filtered = filter_compatible(filtered, entry.module, category)
            if not filtered:
                info(f"No compatible {category}s found for the active module. Showing all instead.")
                filtered = [m for m in all_modules if category_of(m) == category]

        tbl.modules_table(filtered)
