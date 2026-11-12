from teralibs.terasploit.framework.services.printf import error, print_line, warning


class PayloadResolver:
    """Resolves a user-supplied payload string to its module name and class."""

    def __init__(self, modules):
        """Initialise with a module index."""
        self._modules = modules

    def resolve(self, raw):
        """Resolve a raw user payload string to (dotted_name, TerasploitModule)."""
        name = raw.replace("/", ".").removeprefix("modules.")

        if self._modules.get_path(name) is None:
            matches = self._modules.search(name)

            if not matches:
                stem = raw.split("/")[-1].replace("-", "_")
                hits = [m for m in self._modules.list_modules() if m.startswith("payload.") and stem in m]
                if hits:
                    warning(f"payload {raw!r} not found, did you mean:")
                    for m in hits[:5]:
                        print_line(f"    {m.replace('.', '/')}")
                else:
                    error(f"payload not found: {raw!r}  (run 'terax -l payloads' to list)")
                return None, None

            if len(matches) > 1:
                warning(f"ambiguous — {len(matches)} modules match {raw!r}:")
                for m in matches[:10]:
                    print_line(f"    {m.replace('.', '/')}")
                return None, None

            name = matches[0]

        mod = self._modules.load(name)
        if mod is None:
            error(f"failed to load: {name!r}")
            return None, None

        cls = getattr(mod, "TerasploitModule", None)
        if cls is None:
            error(f"{name!r} does not define a TerasploitModule class.")
            return None, None

        return name, cls

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"
