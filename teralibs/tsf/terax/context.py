from teralibs.terasploit.framework.services.printf import error, info, success, warning


class Datastore:
    """Key-value store injected into the context as ctx.datastore."""

    def __init__(self, data):
        """Initialise the store from data, normalising all keys to uppercase."""
        self._d = {k.upper(): v for k, v in data.items()}

    def get_value(self, name, _=None):
        """Return the value stored under name (case-insensitive), or None."""
        return self._d.get(name.upper())

    def all_values(self, _=None):
        """Return a shallow copy of the entire option mapping."""
        return dict(self._d)


class TeraxContext:
    """Lightweight execution context injected into payload.generate(ctx)."""

    def __init__(self, options, *, available_space=1024, verbose=False):
        """Initialise the context with a resolved option mapping."""
        self.datastore = Datastore(options)
        self.job_id = "terax"
        self.session = None
        self.available_space: int | None = available_space
        self._verbose = verbose

    def get_option(self, name, _=None):
        """Return the value of option name, or None if not set."""
        return self.datastore.get_value(name)

    def info(self, msg):
        """Emit an informational message when verbose mode is active."""
        if self._verbose:
            info(msg)

    def success(self, msg):
        """Emit a success message when verbose mode is active."""
        if self._verbose:
            success(msg)

    def warning(self, msg):
        """Emit a warning message unconditionally."""
        warning(msg)

    def error(self, msg):
        """Emit an error message unconditionally."""
        error(msg)
