import contextlib
import os
import readline

from teralibs.terasploit.framework.console.package import DATASTORE, FRAMEWORK_CORE_OPTIONS
from teralibs.terasploit.framework.modules.module_storage import ModuleStorage
from teralibs.terasploit.framework.services.banner import display_banner
from teralibs.terasploit.framework.services.printf import set_verbose, warning
from teralibs.terasploit.framework.thread.handler import ThreadHandler
from teralibs.tsf.utils.path import ModuleIndex


class Terasploit:
    """Core console base."""

    history_file = os.path.join(
        os.path.expanduser("~"),
        ".terasploit",
    )

    console_toggle = True

    def __init__(self, verbose=False, history_length=100, silent_banner=False):
        # Shared state available to all command handlers via self.*.
        self.modules = ModuleIndex()
        self.module_storage = ModuleStorage()
        self.datastore = DATASTORE
        self.thread_handler = ThreadHandler(max_threads=10)

        self.history_length = history_length
        self.silent_banner = silent_banner
        self.startup(verbose)

    def startup(self, verbose):
        """Perform the initial console startup sequence."""
        # Startup sequence - order matters.
        set_verbose(verbose)
        self._register_framework_options(verbose)

        # Apply MAX_THREADS from the framework datastore so operators who
        # persist the option with setg see it honoured on the next launch.
        self._apply_startup_framework_options()

        display_banner(self.modules.list_modules(), silent=self.silent_banner)
        self._load_history()

    def _register_framework_options(self, verbose):
        """Populate the framework scope in the datastore with FRAMEWORK_CORE_OPTIONS."""
        self.datastore.register("framework", FRAMEWORK_CORE_OPTIONS)
        if verbose:
            self.datastore.set_value("VERBOSE", "true", scope="framework")

    def _apply_startup_framework_options(self):
        """Apply framework options that have side effects beyond simple storage."""
        raw_threads = self.datastore.get_value("MAX_THREADS")
        if raw_threads:
            with contextlib.suppress(ValueError, TypeError):
                n = int(raw_threads)
                if n >= 1:
                    self.thread_handler.set_max_threads(n)

    def _load_history(self):
        """Restore the command history file from disk."""
        if os.path.exists(self.history_file):
            try:
                readline.read_history_file(self.history_file)

            except OSError:
                warning(f"Requirement file does not exist: {self.history_file}")

    def _save_history(self):
        """Write the current readline history back to disk."""
        length = self.datastore.get_value("HISTORY_LENGTH")
        try:
            cap = int(length) if length else self.history_length

        except ValueError, TypeError:
            cap = self.history_length

        readline.set_history_length(cap)
        with contextlib.suppress(OSError):
            readline.write_history_file(self.history_file)

    def shutdown(self):
        """Cleanly terminate the console session."""
        self._save_history()
        self.thread_handler.shutdown(timeout=3.0)
        self.module_storage.clear_all()
        self.console_toggle = False
