from collections.abc import Mapping

from teralibs.terasploit.framework.console.helpers import (
    _category_of,
    _filter_compatible,
    _to_path,
)
from teralibs.terasploit.framework.console.terasploit import Terasploit
from teralibs.terasploit.framework.services import tables as tbl
from teralibs.terasploit.framework.services.printf import (
    info,
    print_line,
    warning,
)


class ConsoleRenderer(Terasploit):
    """Mixin that contributes all show sub-command handlers to CLi."""

    category_labels: Mapping = {
        "exploit": "Exploit",
        "auxiliary": "Auxiliary",
        "payload": "Payload",
        "encoder": "Encoder",
        "post": "Post",
        "nop": "NOP",
    }

    def _cmd_show(self, args):
        """Dispatch show sub-commands to their respective display methods."""
        if not args:
            warning("Usage: show <target>  -  options, advanced, targets, auxiliary_modes, all, exploits, payloads, auxiliary, encoders, post, nops.")
            return

        sub = args[0].lower()
        sub_dispatch = {
            "options": self.show_options,
            "advanced": self.show_advanced,
            "evasion": self.show_evasion,
            "targets": self.show_targets,
            "auxiliary_modes": self.show_auxiliary_modes,
            "all": lambda: self.show_category(None),
            "modules": lambda: self.show_category(None),
            "exploits": lambda: self.show_category("exploit"),
            "payloads": lambda: self.show_category("payload"),
            "auxiliary": lambda: self.show_category("auxiliary"),
            "encoders": lambda: self.show_category("encoder"),
            "post": lambda: self.show_category("post"),
            "nops": lambda: self.show_category("nop"),
        }

        handler = sub_dispatch.get(sub)
        if handler is None:
            warning(
                f"Unknown show target '{sub}'.  "
                "Try: options, advanced, targets, auxiliary_modes, all, exploits, payloads, auxiliary, encoders, post, nops."
            )
            return

        module_related_keys = (
            "modules",
            "exploits",
            "auxiliary",
            "payloads",
            "encoders",
            "post",
            "nops",
            "all",
        )

        if sub in module_related_keys:
            print_line(f'\nShow: "{sub}"\n')

        handler()
        print_line("\n")

    def show_options(self):
        """Display basic module options, basic payload options, and targets."""
        entry = self.module_storage.module()
        if entry is None:
            self.show_framework_options()
            return

        category = _category_of(entry.name)
        label = self.category_labels.get(category, category.capitalize())

        if category in ("exploit", "auxiliary", "payload", "post", "evasion"):
            mod_defs = self.datastore.definitions("module")
            mod_vals = self.datastore.all_values("module")

            has_options = entry.module.OPTIONS if category != "post" else bool(mod_defs)
            if has_options and mod_defs:
                tbl.options_table(
                    f"{label} options ({_to_path(entry.name)})",
                    mod_defs,
                    mod_vals,
                )

        pay_entry = self.module_storage.payload()
        if pay_entry is not None:
            if category == "exploit" and entry.module.OPTIONS:
                print_line()

            pay_defs = self.datastore.definitions("payload")
            pay_vals = self.datastore.all_values("payload")

            if pay_defs:
                tbl.options_table(
                    f"Payload options ({_to_path(pay_entry.name)})",
                    pay_defs,
                    pay_vals,
                )

        elif not self.datastore.definitions("module"):
            print_line()
            print_line(f"{label} options ({_to_path(entry.name)}):")
            print_line()
            print_line("   (no options available for this module)")
            print_line()

        enc_entry = self.module_storage.encoder()
        if enc_entry is not None:
            if pay_entry is not None:
                print_line()

            enc_defs = self.datastore.definitions("encoder")
            enc_vals = self.datastore.all_values("encoder")
            if enc_defs:
                tbl.options_table(f"Encoder options ({_to_path(enc_entry.name)})", enc_defs, enc_vals)

        targets = getattr(entry.module, "TARGET", None)
        if targets:
            print_line()
            tbl.targets_table(targets)

    def show_advanced(self):
        """Display advanced options for the active module and its payload."""
        entry = self.module_storage.module()
        if entry is None:
            warning("No module loaded.")
            return

        category = _category_of(entry.name)
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

    def show_module_advanced(self, entry):
        """Render the advanced options table for the active module."""

        name = entry.name
        category = _category_of(name)

        label = self.category_labels.get(category, category.capitalize())
        title = f"{label} advanced options ({_to_path(name)})"

        defs = self.datastore.definitions("module_advanced")
        vals = self.datastore.all_values("module_advanced")

        if defs:
            tbl.options_table(title, defs, vals)
            return

        info(f"No advanced options for {_to_path(name)}.")

    def show_payload_advanced(self):
        """Render the advanced options table for the active payload, if any."""
        pay_entry = self.module_storage.payload()
        if pay_entry is None:
            return

        defs = self.datastore.definitions("payload_advanced")
        vals = self.datastore.all_values("payload_advanced")
        if defs:
            title = f"Payload advanced options ({_to_path(pay_entry.name)})"
            tbl.options_table(title, defs, vals)

    def show_encoder_summary(self):
        """Print a one-line summary of the active encoder, if any."""
        enc_entry = self.module_storage.encoder()
        if enc_entry is None:
            return

        enc_obj = enc_entry.module
        rank = enc_obj.RANK
        rank_lbl = getattr(rank, "label", lambda: str(rank))()
        arch_str = ", ".join(enc_obj.ARCH or []) or "generic"
        description = getattr(enc_obj, "DESCRIPTION", "")

        print_line(f"\nActive encoder: {_to_path(enc_entry.name)} [rank={rank_lbl}, arch={arch_str}]")
        print_line(f"Description   : {description[:90]}")

    # Evasion option display

    def show_evasion(self):
        """Display evasion options for the active module and its payload."""
        entry = self.module_storage.module()
        if entry is None:
            self.show_category("evasion")
            return

        category = _category_of(entry.name)
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
        category = _category_of(name)

        label = self.category_labels.get(category, category.capitalize())
        title = f"{label} evasion options ({_to_path(name)})"

        defs = self.datastore.definitions("module_evasion")
        vals = self.datastore.all_values("module_evasion")

        if defs:
            tbl.options_table(title, defs, vals)
            return

        info(f"No evasion options for {_to_path(name)}.")

    def show_payload_evasion(self):
        """Render the evasion options table for the active payload, if any."""
        pay_entry = self.module_storage.payload()
        if pay_entry is None:
            return

        defs = self.datastore.definitions("payload_evasion")
        vals = self.datastore.all_values("payload_evasion")
        if defs:
            title = f"Payload evasion options ({_to_path(pay_entry.name)})"
            tbl.options_table(title, defs, vals)

    def show_framework_options(self):
        """Display the framework core options stored in the framework scope."""
        fw_defs = self.datastore.definitions("framework")
        fw_vals = self.datastore.all_values("framework")

        if fw_defs:
            tbl.options_table("Framework core options", fw_defs, fw_vals)
            return

        print_line()
        info("No framework options are registered.")
        print_line()

    def _show_module_settings(self, attr, title, module_name):
        """Display module settings like exploit targets or auxiliary modes."""
        entry = self.module_storage.module()
        if entry is None:
            warning(f"No module loaded. Use '{module_name}' module first.")
            return

        settings = getattr(entry.module, attr, None)
        if not settings:
            warning(f"This {module_name} module does not declare any {title.lower()}")
            return

        tbl.targets_table(settings, title=title)

    def show_auxiliary_modes(self):
        """Display the auxiliary modes."""
        self._show_module_settings("AUXILIARY_MODE", "Auxiliary modes", "auxiliary")

    def show_targets(self):
        """Display the targets declared by the exploit module."""
        self._show_module_settings("TARGET", "Targets", "exploit")

    def show_category(self, category):
        """Display a modules table filtered by category."""
        all_modules = self.modules.list_modules()
        filtered = [m for m in all_modules if _category_of(m) == category] if category is not None else all_modules

        entry = self.module_storage.module()
        if entry is not None and category in ("payload", "encoder"):
            filtered = _filter_compatible(filtered, entry.module, category)

            if not filtered:
                info(f"No compatible {category}s found for the active module. Showing all instead.")
                filtered = [m for m in all_modules if _category_of(m) == category]

        tbl.modules_table(filtered)
