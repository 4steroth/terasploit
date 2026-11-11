import dataclasses

from teralibs.terasploit.framework.console.helpers import _to_path
from teralibs.terasploit.framework.console.terasploit import Terasploit
from teralibs.terasploit.framework.encoder.factory import EncoderFactory
from teralibs.terasploit.framework.encoder.package import Encoder
from teralibs.terasploit.framework.modules.payload_validator import payload_validate
from teralibs.terasploit.framework.options.storage import (
    DRIVER_ADVANCED_OPTIONS,
    OPTION_REGISTRY,
    PAYLOAD_ADVANCED_OPTIONS,
    PAYLOAD_EVASION_OPTIONS,
    POST_MODULE_OPTIONS,
    REVERSE_TCP_ADVANCED_OPTIONS,
    STAGER_ADVANCED_OPTIONS,
    Option,
)
from teralibs.terasploit.framework.services import tables as tbl
from teralibs.terasploit.framework.services.printf import (
    RED,
    RESET,
    debug,
    error,
    info,
    print_line,
    set_timestamp,
    set_verbose,
    success,
    warning,
)
from teralibs.tsf.utils.exception import ModuleInitializationError


def _resolve_keys(keys):
    """Resolve a module's option key list into a list of Option objects."""
    resolved = []
    for key in keys:
        if isinstance(key, Option):
            OPTION_REGISTRY.setdefault(key.key, key)
            resolved.append(key)
            continue

        if isinstance(key, str):
            name, overrides = key, None
        elif isinstance(key, tuple) and len(key) == 2 and isinstance(key[0], str) and isinstance(key[1], dict):
            name, overrides = key
        else:
            warning(f"Unexpected item in OPTIONS list: {key!r} ({type(key).__name__}) - skipping.")
            continue

        opt = OPTION_REGISTRY.get(name.upper())
        if opt is None:
            warning(f"Option key {name!r} not found in OPTION_REGISTRY - skipping.")
            continue

        if overrides is None:
            resolved.append(opt)
            continue

        try:
            resolved.append(dataclasses.replace(opt, **overrides))
        except TypeError as exc:
            warning(f"Invalid override for {name!r} - skipping. ({exc})")

    return resolved


class ConsoleLoader(Terasploit):
    """Mixin that contributes module/payload/encoder loading and option-set command handlers to CLi."""

    def resolve_module_name(self, args):
        """Validate *args* and resolve a raw module name to a canonical dotted path."""
        if not args:
            warning("Usage: use <module_name>")
            return None

        raw = args[0].replace("/", ".")

        # Encoder paths are handled by a dedicated loader - signal the caller.
        if raw.startswith("encoder.") or args[0].startswith("encoder/"):
            return "__encoder__"

        if self.modules.get_path(raw) is not None:
            return raw

        matches = self.modules.search(raw)
        if not matches:
            error(f"Module not found: {args[0]!r}")
            return None

        if len(matches) > 1:
            info(f"Ambiguous - {len(matches)} modules match {args[0]!r}:")
            tbl.modules_table(matches)
            print_line("\n")
            return None

        return matches[0]

    def apply_framework_option(self, name: str, value) -> None:
        """Apply the immediate side effect of a framework option change."""
        val_lower = str(value).lower().strip()
        truthy = val_lower in ("true", "yes", "1", "on")

        handlers = {
            "VERBOSE": lambda: self._handle_verbose(truthy),
            "TIMESTAMP_OUTPUT": lambda: self._handle_timestamp(truthy),
            "MAX_THREADS": lambda: self._handle_max_threads(value),
            "SESSION_TIMEOUT": lambda: self._handle_session_timeout(value),
            "WORKSPACE": lambda: self._handle_workspace(value),
        }

        if name in ("PROMPT", "PROMPT_CHAR"):
            debug(f"Prompt updated: {name} = {value!r}")
        elif name in handlers:
            handlers[name]()

    def _cmd_use(self, args):
        """Load a module into the active module slot."""
        resolved = self.resolve_module_name(args)
        if resolved is None:
            return

        if resolved == "__encoder__":
            self._load_encoder(args[0])
            return

        if resolved.startswith("payload"):
            self._load_payload(args[0], silent=False)
            return

        cls = self._import_module_class(resolved)
        if cls is None:
            return

        obj = self._instantiate_and_allocate_storage(resolved, cls, args)
        if obj is None:
            return

        self._register_standard_module_scopes(resolved, obj)
        self._apply_module_defaults(resolved, obj)

    def _import_module_class(self, resolved: str):
        """Loads the raw file module structure and extracts the TerasploitModule class."""
        mod = self.modules.load(resolved)
        if mod is None:
            error(f"Failed to load module file: {resolved!r}")
            return None

        cls = getattr(mod, "TerasploitModule", None)
        if cls is None:
            error(f"Module {resolved!r} does not define a TerasploitModule class.")
            return None

        return cls

    def _instantiate_and_allocate_storage(self, resolved: str, cls: type, args: list):
        """Instantiates the module object securely and balances active slot context storage."""
        try:
            obj = cls()
        except ModuleInitializationError as exc:
            error(f"Module initialisation error: {exc}")
            return None

        # Clear existing module first before setting the new one to avoid options duplicates
        if self.module_storage.module() is not None:
            self._cmd_back(args)

        self.module_storage.set_module(resolved, obj)
        debug(f"using module: {_to_path(resolved)}")
        return obj

    def _register_standard_module_scopes(self, resolved: str, obj) -> None:
        """Reset and repopulate the module, advanced and evasion scopes."""
        self.datastore.clear_scope("module")
        if obj.OPTIONS:
            self.datastore.register("module", _resolve_keys(obj.OPTIONS))
        # Post modules expose SESSION in "show options" and in missing_required.
        if resolved.startswith("post"):
            self.datastore.register("module", POST_MODULE_OPTIONS)

        self.datastore.clear_scope("module_advanced")
        if resolved.startswith("exploit"):
            self.datastore.register("module_advanced", DRIVER_ADVANCED_OPTIONS)
        if obj.ADVANCED_OPTIONS:
            self.datastore.register("module_advanced", _resolve_keys(obj.ADVANCED_OPTIONS))

        self.datastore.clear_scope("module_evasion")
        if obj.EVASION_OPTIONS:
            self.datastore.register("module_evasion", _resolve_keys(obj.EVASION_OPTIONS))

    def _apply_module_defaults(self, resolved: str, obj) -> None:
        """Applies default target/mode selection and auto-loads a payload."""
        if resolved.startswith("exploit"):
            self.datastore.set_value("TARGET", obj.TARGET[0][1], "module")

        if resolved.startswith("auxiliary"):
            self.datastore.set_value("AUXILIARY_MODE", obj.AUXILIARY_MODE[0][1], "module")

        default_payload = getattr(obj, "DEFAULT_PAYLOAD", None)
        if default_payload and not self.module_storage.has_payload():
            info(f"Auto-loading default payload: {default_payload}")
            self._load_payload(default_payload, silent=True)

    def _cmd_back(self, _):
        """Unload the active module and return to the root prompt."""
        module = self.module_storage.module()

        if module and hasattr(module, "name"):
            self.module_storage.clear_module()
            self.module_storage.clear_payload()
            self.module_storage.clear_encoder()

            for scope in (
                "module",
                "module_advanced",
                "module_evasion",
                "payload",
                "payload_advanced",
                "payload_evasion",
                "encoder",
            ):
                self.datastore.clear_scope(scope)

            info(f"Unloaded: {_to_path(module.name)}")

        if not self.module_storage.has_module():
            warning("No module is currently loaded.")

    def _cmd_set(self, args):
        """Assign a value to an option in the active datastore."""
        if len(args) < 2:
            warning("Usage: set <option> <value>")
            return

        name = args[0].upper()
        value = " ".join(args[1:])

        delegated = {
            "PAYLOAD": self._load_payload,
            "ENCODER": self._load_encoder,
            "TARGET": self._set_target,
            "MODE": self._set_auxiliary_mode,
        }
        delegate = delegated.get(name)
        if delegate is not None:
            delegate(value)
            return

        self._set_generic(name, value)

    def _set_generic(self, name, value):
        """Write *name* / *value* to the appropriate scope and report the result."""
        if not self.module_storage.has_module():
            result = self.datastore.validate(name, value, scope="framework")
            if result.ok:
                self.datastore.set_value(name, value, scope="framework")
                self.apply_framework_option(name, value)
                print_line(f"{name} => {value}")
                return

            warning(result.reason)
            return

        result = self.datastore.validate(name, value)
        if result.ok:
            self.datastore.set_value(name, value)
            print_line(f"{name} => {value}")
            return

        warning(result.reason)

    def _cmd_unset(self, args):
        """Reset a module-scope option to empty (None)."""
        if not args:
            warning("Usage: unset <option>")
            return

        name = args[0].upper()

        if self.datastore.set_value(name, None):
            info(f"Unset: {name}")
            return

        warning(f"Option '{name}' not found in any active scope.")

    def _handle_verbose(self, truthy: bool) -> None:
        """Configures framework-wide global execution logging verbosity."""
        set_verbose(truthy)
        level = "enabled" if truthy else "disabled"
        info(f"Verbose output {level}.")

    def _handle_timestamp(self, truthy: bool) -> None:
        """Configures stdout log decoration with date/time prefixes."""
        set_timestamp(truthy)
        level = "enabled" if truthy else "disabled"
        info(f"Timestamp output {level}.")

    def _handle_max_threads(self, value) -> None:
        """Dynamically expands or cuts operational execution worker pool queues."""
        try:
            new_max = int(value)
            if new_max < 1:
                raise ValueError("must be >= 1")

            self.thread_handler.set_max_threads(new_max)
            info(f"Thread pool resized to {new_max} worker(s).")

        except (ValueError, TypeError) as exc:
            warning(f"MAX_THREADS must be a positive integer: {exc}")

    def _handle_session_timeout(self, value) -> None:
        """Alters downstream shell collection activity keep-alive timers."""
        try:
            seconds = float(value)
            if seconds < 0:
                raise ValueError("must be >= 0")

            state = "disabled" if seconds == 0 else f"set to {seconds}s"
            info(f"Session idle timeout {state}.")

        except ValueError, TypeError:
            warning(f"SESSION_TIMEOUT must be a number, got: {value!r}")

    def _handle_workspace(self, value) -> None:
        """Tracks the operational targets output file organizational paths."""
        if value:
            info(f"Workspace set to '{str(value).strip()}'. Session files will be saved under session/{str(value).strip()}/.")
            return

        info("Workspace cleared - session files will be saved to session/.")

    def _load_payload(self, raw, silent=False):
        """Load a payload module and register its options into the datastore."""
        name = raw.replace("/", ".")

        if self.modules.get_path(name) is None:
            matches = self.modules.search(name)

            if not matches:
                error(f"Payload not found: {raw!r}")
                return

            if len(matches) > 1:
                warning(f"Ambiguous payload - {len(matches)} match(es):")
                for match in matches[:8]:
                    print_line(f"   {_to_path(match)}")
                return

            name = matches[0]

        mod = self.modules.load(name)
        if mod is None:
            error(f"Failed to load payload file: {name!r}")
            return

        cls = getattr(mod, "TerasploitModule", None)
        if cls is None:
            error(f"Payload {name!r} does not define a TerasploitModule class.")
            return

        obj = cls()

        module_entry = self.module_storage.module()
        if module_entry is not None:
            result = payload_validate(module_entry.module, obj)
            if not result.compatible:
                error(f"Payload {_to_path(name)} is incompatible with {_to_path(module_entry.name)}:")
                for reason in result.reasons:
                    print_line(f"   {RED}[-]{RESET} {reason}")
                return

        self._payload_options(name, obj)

        if not silent:
            print_line(f"PAYLOAD => {_to_path(name)}")

    def _payload_options(self, name, obj):
        """Register a payload's options into the datastore scopes."""
        self.module_storage.set_payload(name, obj)
        self.datastore.clear_scope("payload")
        self.datastore.clear_scope("payload_advanced")
        self.datastore.clear_scope("payload_evasion")

        if obj.OPTIONS:
            self.datastore.register("payload", _resolve_keys(obj.OPTIONS))

        # Transport-level advanced options apply to every payload; the
        # payload's own ADVANCED_OPTIONS layer on top.
        self.datastore.register("payload_advanced", PAYLOAD_ADVANCED_OPTIONS)
        if obj.ADVANCED_OPTIONS:
            self.datastore.register("payload_advanced", _resolve_keys(obj.ADVANCED_OPTIONS))

        if getattr(obj.HANDLER, "HANDLER_TYPE", None) == "reverse":
            self.datastore.register("payload_advanced", REVERSE_TCP_ADVANCED_OPTIONS)

        if obj.PAYLOAD_TYPE == "stager":
            self.datastore.register("payload_advanced", STAGER_ADVANCED_OPTIONS)

        # Evasion options are opt-in per payload via EVASION_OPTIONS, not dumped globally.
        if obj.STAGE_ENCODING is True:
            self.datastore.register("payload_advanced", PAYLOAD_EVASION_OPTIONS)

        if obj.EVASION_OPTIONS:
            self.datastore.register("payload_evasion", _resolve_keys(obj.EVASION_OPTIONS))

        if obj.STAGE_ENCODING is False and obj.EVASION_OPTIONS:
            warning("Evasion options found in module metadata, but the module does not support stage encoding.")

    def _load_encoder(self, raw, silent=False):
        """Load an encoder module and register its options into the datastore."""
        name = raw.replace("/", ".").strip(".")
        if not name.startswith("encoder."):
            name = "encoder." + name

        if self.modules.get_path(name) is None:
            matches = self.modules.search(name)
            if not matches:
                error(f"Encoder not found: {raw!r}")
                return
            if len(matches) > 1:
                warning(f"Ambiguous encoder - {len(matches)} match(es):")
                for match in matches[:8]:
                    print_line(f"   {_to_path(match)}")
                return
            name = matches[0]

        mod = self.modules.load(name)
        if mod is None:
            error(f"Failed to load encoder file: {name!r}")
            return

        cls_obj = getattr(mod, "TerasploitModule", None)
        if cls_obj is None:
            error(f"Encoder {name!r} does not define a TerasploitModule class.")
            return
        if not (isinstance(cls_obj, type) and issubclass(cls_obj, Encoder)):
            error(f"Encoder {name!r}: TerasploitModule must inherit Encoder.")
            return

        try:
            obj = cls_obj()
        except ModuleInitializationError as exc:
            error(f"Encoder initialisation error: {exc}")
            return

        EncoderFactory.register(obj)
        self.module_storage.set_encoder(name, obj)

        # Record the active encoder name in the payload_advanced scope using
        # the public datastore API so it is visible in 'show options'.
        self.datastore.set_value("ENCODER", obj.NAME, scope="payload_advanced")

        # Load all options to register in datastore.
        self._encoder_options(obj)

        if not silent:
            rank_label = getattr(obj.RANK, "label", lambda: str(obj.RANK))()
            arch_str = ", ".join(obj.ARCH) if obj.ARCH else "generic"
            print_line(f"ENCODER => {_to_path(name)}")
            success(f"Encoder loaded: {_to_path(name)} [rank={rank_label}, arch={arch_str}]")

    def _encoder_options(self, obj):
        """Load all available options for encoder."""

        # Clear all current encoder options.
        self.datastore.clear_scope("encoder")

        if obj.OPTIONS:
            self.datastore.register("encoder", _resolve_keys(obj.OPTIONS))

        if obj.ADVANCED_OPTIONS:
            self.datastore.register("payload_advanced", _resolve_keys(obj.ADVANCED_OPTIONS))

        if obj.EVASION_OPTIONS:
            self.datastore.register("payload_evasion", _resolve_keys(obj.EVASION_OPTIONS))

    def _select_indexed_option(self, value, setup) -> None:
        """Select an item from a module's indexed option list by numeric ID."""
        attr_name, not_loaded_label, no_items_label, numeric_label, store_tuple_value, double_space_quirk = setup

        module_entry = self.module_storage.module()
        if module_entry is None:
            warning(f"No module loaded - cannot set {not_loaded_label}.")
            return

        items = getattr(module_entry.module, attr_name, [])
        if not items:
            warning(f"This module does not declare any {no_items_label}.")
            return

        try:
            tid = int(value)

        except ValueError:
            error(f"{numeric_label} must be a numeric ID, got: {value!r}")
            return

        valid_ids = [t[0] for t in items]
        if tid not in valid_ids:
            spacer = "  " if double_space_quirk else " "
            error(f"Invalid target ID {tid}.{spacer}Valid IDs: {valid_ids}")
            return

        self.datastore.set_value(attr_name, items[tid][1] if store_tuple_value else tid, "module")
        print_line(f"{attr_name} => {tid}  ({next(t[1] for t in items if t[0] == tid)})")

    def _set_target(self, value):
        """Select the active target by numeric ID."""
        self._select_indexed_option(
            value,
            (
                "TARGET",
                "TARGET",
                "targets",
                "TARGET",
                True,
                False,
            ),
        )

    def _set_auxiliary_mode(self, value):
        """Select the active auxiliary mode by numeric ID."""
        self._select_indexed_option(
            value,
            (
                "AUXILIARY_MODE",
                "AUXILIARY MODE",
                "auxiliary modes",
                "Auxiliary Mode",
                False,
                True,
            ),
        )
