from terasploit.console.helpers import to_path
from terasploit.module.runner import ModuleRunner
from terasploit.ui.printf import (
    RED,
    RESET,
    error,
    info,
    print_line,
    warning,
)


class ExecutionCommands:
    """Handle execution console commands."""

    def __init__(self, console) -> None:
        self.console = console
        self.runner = ModuleRunner(console, self._on_session_opened)

    def cmd_check(self, _):
        """Probe the target for vulnerability."""
        entry = self._active_module()
        if entry is None:
            return
        if not hasattr(entry.module, "check"):
            warning(f"{entry.name} does not implement a check() method. Run 'run' to execute the full exploit.")
            return

        is_exploit = entry.name.startswith("exploit")
        payload_obj = self._resolve_payload_obj() if is_exploit else None
        if not is_exploit and not hasattr(entry.module, "run"):
            warning(f"Auxiliary module '{to_path(entry.name)}' has no 'run' method.")
            return

        missing = self._missing_required_options(is_exploit)
        if missing:
            error(f"Required option(s) not set: {RED}{', '.join(missing)}{RESET}.")
            return

        task_id = self.runner.check(entry, payload_obj)
        if task_id is not None:
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
        if not hasattr(entry.module, "run"):
            warning(f"Module '{to_path(entry.name)}' has no 'run' method.")
            return

        # Payload only relevant for exploit modules
        payload_obj = self._resolve_payload_obj() if is_exploit else None

        # Execute the module
        self._run_module(entry, payload_obj)

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

    def _run_module(self, entry, payload_obj):
        """Submit the active module through ModuleRunner and wait for completion."""
        task_id = self.runner.run(entry, payload_obj)
        if task_id is not None:
            self._async_job_runner(task_id)

    def _run_post_module(self):
        """Submit the active post module through ModuleRunner and wait for completion."""
        task_id = self.runner.run_post()
        if task_id is not None:
            self._async_job_runner(task_id)

    def _async_job_runner(self, task_id):
        """Act as the stdout proxy."""
        cancelled = False
        interrupt = 0
        while True:
            try:
                if self.console.thread_handler.wait_until_done(task_id, poll=0.15):
                    break
                if self.console.thread_handler.output_bus.pending() > 0:
                    self.console.flush_job_output()
            except KeyboardInterrupt:
                interrupt += 1
                print_line()
                if not cancelled:
                    info("Interrupt received. Python cannot safely force-terminate threads. Waiting for task to finish...")
                    self.console.thread_handler.kill_task(task_id)
                    cancelled = True
                    continue
            if interrupt > 1:
                info("Received more than 1 interrupt, returning to console. The task may still be running...")
                break

        # Final drain so the last events (session opened, errors) are visible.
        self.console.flush_job_output()

    def _on_session_opened(self, session):
        """Called by the ExploitDriver when a new session is established."""
        session_id = session.session_id
        addr = session.transport.addr

        self.console.thread_handler.output_bus.emit(
            "session",
            "success",
            f"Session {session_id} opened ({addr[0]}:{addr[1]})",
        )
