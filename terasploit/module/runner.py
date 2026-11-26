from functools import partial

from extension.module.context import (
    AuxiliaryContext,
    AuxiliaryContextDeps,
    ExploitContext,
    ExploitContextDeps,
    PostContext,
    PostContextDeps,
)
from terasploit.console.helpers import to_path
from terasploit.exploit.driver import DriverDeps, ExploitDriver, get_session
from terasploit.ui.printf import debug, error, warning


class ModuleRunner:
    """Create module contexts and submit module work through the existing job system."""

    def __init__(self, console, session_callback):
        self.console = console
        self.session_callback = session_callback

    def check(self, entry, payload_obj=None):
        """Submit the exploit-check or auxiliary-check execution path."""
        if entry.name.startswith("exploit"):
            driver = partial(self._exploit_check_worker, entry, payload_obj)
        else:
            driver = partial(self._auxiliary_worker, entry)
        return self._submit(driver, "Driver error")

    def run(self, entry, payload_obj=None):
        """Submit an auxiliary module or start the exploit driver."""
        debug(f"Running module: {to_path(entry.name)}")
        is_exploit = entry.name.startswith("exploit") or entry.name.startswith("payload")

        if is_exploit:
            driver = ExploitDriver(
                DriverDeps(
                    module_obj=entry.module,
                    payload_obj=payload_obj,
                    datastore=self.console.datastore,
                    thread_handler=self.console.thread_handler,
                    output_bus=self.console.thread_handler.output_bus,
                    session_callback=self.session_callback,
                    intelligence=self.console.intelligence,
                    loot=self.console.loot,
                )
            )
        else:
            driver = partial(self._auxiliary_worker, entry)

        return self._submit(driver, "Driver error")

    def run_post(self):
        """Resolve the selected session and submit the active post module."""
        session_id = self.console.datastore.get_value("SESSION")
        entry = self.console.module_storage.module()

        session = get_session(session_id) if session_id else None
        if session is None:
            error(f"Session {session_id!r} not found. Use 'sessions' to list open sessions.")
            return None
        if not session.runtime.alive:
            error(f"Session {session_id!r} is no longer alive.")
            return None

        driver = partial(self._post_worker, entry, session)
        return self._submit(driver, "Post module error")

    def _exploit_check_worker(self, entry, payload_obj, worker_ctx):
        ctx = ExploitContext(
            ExploitContextDeps(
                job_id=worker_ctx.job_id,
                module_obj=entry.module,
                payload_obj=payload_obj,
                datastore=self.console.datastore,
                bus=worker_ctx.bus,
                intelligence=self.console.intelligence,
                loot=self.console.loot,
            )
        )
        entry.module.check(ctx)

    def _auxiliary_worker(self, entry, worker_ctx):
        ctx = AuxiliaryContext(
            AuxiliaryContextDeps(
                job_id=worker_ctx.job_id,
                bus=worker_ctx.bus,
                datastore=self.console.datastore,
                intelligence=self.console.intelligence,
                loot=self.console.loot,
            )
        )
        if entry and hasattr(entry, "module"):
            entry.module.run(ctx)
        else:
            error("Module has no 'run' method.")

    def _post_worker(self, entry, session, worker_ctx):
        ctx = PostContext(
            PostContextDeps(
                job_id=worker_ctx.job_id,
                bus=worker_ctx.bus,
                datastore=self.console.datastore,
                session=session,
                intelligence=self.console.intelligence,
                loot=self.console.loot,
            )
        )
        if entry and hasattr(entry, "module"):
            entry.module.run(ctx)
        else:
            error("Module has no 'run' method.")

    def _submit(self, driver, error_prefix):
        """Submit a worker or exploit driver and preserve existing failure cleanup."""
        try:
            if isinstance(driver, ExploitDriver):
                return driver.run()
            return self.console.thread_handler.submit(driver)
        except (ValueError, OSError) as exc:
            error(f"{error_prefix}: {exc}")
            if not isinstance(driver, ExploitDriver):
                return None
            if hasattr(driver, "stop"):
                driver.stop()
            else:
                warning("Driver has no 'stop()' method - cannot clean up.")
            return None
