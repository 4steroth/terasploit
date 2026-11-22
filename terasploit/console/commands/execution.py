import contextlib

from extension.module.context import (
    AuxiliaryContext,
    AuxiliaryContextDeps,
    ExploitContext,
    ExploitContextDeps,
    PostContext,
    PostContextDeps,
)
from terasploit.console.base import BaseConsole
from terasploit.console.helpers import to_path
from terasploit.exploit.driver import (
    DriverDeps,
    ExploitDriver,
    get_session,
)
from terasploit.ui.printf import (
    RED,
    RESET,
    debug,
    error,
    print_line,
    warning,
)


class ExecutionCommands:
    """Handle execution console commands."""

    def __init__(self, console: BaseConsole) -> None:
        """Bind this command group to the shared console."""
        self.console = console

    def cmd_check(self, _):
        """Probe the target for vulnerability."""
        entry = self._active_module()
        if entry is None:
            return

        if not hasattr(entry.module, "check"):
            warning(f"{entry.name} does not implement a check() method. Run 'run' to execute the full exploit.")
            return

        is_exploit = entry.name.startswith("exploit")

        # Payload only relevant for exploit modules
        payload_obj = self._resolve_payload_obj() if is_exploit else None

        if not is_exploit and not hasattr(entry.module, "run"):
            warning(f"Auxiliary module '{to_path(entry.name)}' has no 'run' method.")
            return

        missing = self._missing_required_options(is_exploit)
        if missing:
            error(f"Required option(s) not set: {RED}{', '.join(missing)}{RESET}.")
            return

        if is_exploit:

            def _run_exploit(worker_ctx):
                """Run the exploit check inside a worker context."""
                _ctx = ExploitContext(
                    ExploitContextDeps(
                        job_id=worker_ctx.job_id,
                        module_obj=entry.module,
                        payload_obj=payload_obj,
                        datastore=self.console.datastore,
                        bus=worker_ctx.bus,
                    )
                )
                entry.module.check(_ctx)

            driver = _run_exploit

        else:

            def _run_auxiliary(worker_ctx):
                """Run the auxiliary check inside a worker context."""
                _ctx = AuxiliaryContext(
                    AuxiliaryContextDeps(
                        job_id=worker_ctx.job_id,
                        bus=worker_ctx.bus,
                        datastore=self.console.datastore,
                    )
                )
                entry.module.run(_ctx)

            driver = _run_auxiliary

        try:
            task_id = self.console.thread_handler.submit(driver)
        except (ValueError, OSError) as exc:
            self._cleanup_failed_driver(driver, exc)
            return

        self._async_job_runner(task_id)

    def cmd_run(self, _):
        """Execute the active module and block until it finishes."""
        entry = self._active_module()
        if entry is None:
            return

        # Run post module
        is_post = entry.name.startswith("post")
        if is_post is True:
            self._run_post_module()
            return

        is_exploit = entry.name.startswith("exploit") or entry.name.startswith("payload")

        missing = self._missing_required_options(is_exploit)
        if missing:
            error(f"Required option(s) not set: {RED}{', '.join(missing)}{RESET}.")
            return

        # Payload only relevant for exploit modules
        payload_obj = self._resolve_payload_obj() if is_exploit else None

        if not hasattr(entry.module, "run"):
            warning(f"Module '{to_path(entry.name)}' has no 'run' method.")
            return

        # Execute the module
        self._run_module(entry, is_exploit, payload_obj)

    def _active_module(self):
        """Return the active module entry, warning if none is loaded."""
        entry = self.console.module_storage.module()
        if entry is None:
            warning("No module loaded.  Use 'use <module>' first.")
        return entry

    def _resolve_payload_obj(self):
        """Resolve the active payload's module object, falling back to the module itself."""
        payload_entry = self.console.module_storage.payload() or self.console.module_storage.module()
        return payload_entry.module if payload_entry is not None else None

    def _missing_required_options(self, is_exploit):
        """Return unset required option names, including payload options for exploits."""
        missing = self.console.datastore.missing_required("module")
        if is_exploit:
            missing += self.console.datastore.missing_required("payload")
        return missing

    def _cleanup_failed_driver(self, driver, exc):
        """Log a driver submission failure and stop the driver if it supports cleanup."""
        error(f"Driver error: {exc}")
        if isinstance(driver, ExploitDriver):
            if hasattr(driver, "stop"):
                driver.stop()
            else:
                warning("Driver has no stop() method - cannot clean up.")

    def _run_module(self, entry, is_exploit, payload_obj):
        """Execute auxiliary/exploit modules."""
        debug(f"Running module: {to_path(entry.name)}")

        driver = None
        if is_exploit is True:
            driver = ExploitDriver(
                DriverDeps(
                    module_obj=entry.module,
                    payload_obj=payload_obj,
                    datastore=self.console.datastore,
                    thread_handler=self.console.thread_handler,
                    output_bus=self.console.thread_handler.output_bus,
                    session_callback=self._on_session_opened,
                )
            )

        else:

            def _run_auxiliary(worker_ctx):
                """Run the auxiliary module inside a worker context."""
                _ctx = AuxiliaryContext(
                    AuxiliaryContextDeps(
                        job_id=worker_ctx.job_id,
                        bus=worker_ctx.bus,
                        datastore=self.console.datastore,
                    )
                )
                if entry and hasattr(entry, "module"):
                    entry.module.run(_ctx)
                else:
                    error("Module has no 'run' method.")

            driver = _run_auxiliary

        try:
            task_id = driver.run() if isinstance(driver, ExploitDriver) else self.console.thread_handler.submit(driver)

        except (ValueError, OSError) as exc:
            self._cleanup_failed_driver(driver, exc)
            return

        self._async_job_runner(task_id)

    def _run_post_module(self):
        """Running post module gets a standalone method because it is different to auxiliary and exploit context."""
        session_id = self.console.datastore.get_value("SESSION")
        entry = self.console.module_storage.module()

        session = get_session(session_id) if session_id else None
        if session is None:
            error(f"Session {session_id!r} not found. Use 'sessions' to list open sessions.")
            return

        if not session.runtime.alive:
            error(f"Session {session_id!r} is no longer alive.")
            return

        def _run_post(worker_ctx):
            """Run the post module inside a worker context."""
            post_ctx = PostContext(
                PostContextDeps(
                    job_id=worker_ctx.job_id,
                    bus=worker_ctx.bus,
                    datastore=self.console.datastore,
                    session=session,
                )
            )
            if entry and hasattr(entry, "module"):
                entry.module.run(post_ctx)
            else:
                error("Module has no 'run' method.")

        try:
            task_id = self.console.thread_handler.submit(_run_post)

        except (ValueError, OSError) as exc:
            error(f"Post module error: {exc}")
            return

        self._async_job_runner(task_id)

    def _async_job_runner(self, task_id):
        """Acts as the stdout proxy."""
        try:
            while not self.console.thread_handler.wait_until_done(task_id, poll=0.15):
                if self.console.thread_handler.output_bus.pending() > 0:
                    self.console.flush_job_output()

        except KeyboardInterrupt:
            print_line()
            warning("Interrupt - killing job.")

            self.console.thread_handler.kill_task(task_id)
            while not self.console.thread_handler.wait_until_done(task_id, poll=0.15):
                # We ignore any ctrl+c coming. You executed it, finish it.
                with contextlib.suppress(KeyboardInterrupt):
                    if self.console.thread_handler.output_bus.pending() > 0:
                        self.console.flush_job_output()

        # Final drain so the last events (session opened, errors) are visible.
        self.console.flush_job_output()

    def _on_session_opened(self, session):
        """Called by the ExploitDriver when a new session is established."""
        session_id = session.session_id
        addr = session.transport.addr

        self.console.thread_handler.output_bus.emit("session", "success", f"Session {session_id} opened ({addr[0]}:{addr[1]})")
