import contextlib
import time

from terasploit.exploit.driver import (
    all_sessions,
    get_session,
    remove_session,
)
from terasploit.exploit.entry import open_shell
from terasploit.exploit.sessions import history
from terasploit.ui import tables as tbl
from terasploit.ui.printf import (
    CYAN,
    GREEN,
    RED,
    RESET,
    YELLOW,
    debug,
    error,
    info,
    print_line,
    success,
    warning,
)


JOB_STATUS_COLORS = {
    "queued": YELLOW,
    "running": CYAN,
    "completed": GREEN,
    "failed": RED,
    "killed": RED,
}


class SessionsCommands:
    """Handle sessions console commands."""

    def __init__(self, console) -> None:
        self.console = console

    def cmd_sessions(self, args):
        """List all currently open Shell Sessions."""
        if args and args[0] == "-C":
            self._run_session_command(args[1:])
            return
        if args and args[0] in {"-H", "--history"}:
            self._browse_history(args[1:])
            return
        if args:
            warning("Usage: sessions [-H [id] [-w workspace] [-p platform]] | -C <id> <command>")
            return

        sessions = all_sessions()
        print_line()
        if not sessions:
            info("No open sessions.")
            print_line()
            return

        self._print_sessions_table(sessions)
        print_line()

    def _browse_history(self, args):
        """Browse persisted session history without affecting live sessions."""
        workspace = self.console.datastore.get_value("WORKSPACE") or "default"
        parsed = self._parse_history_args(args, workspace)
        if parsed is None:
            return

        workspace, platform, identifier = parsed
        if identifier:
            self._show_history_record(identifier, workspace)
            return

        self._list_history_records(workspace, platform)

    def _parse_history_args(self, args, workspace):
        """Parse `sessions -H` arguments."""
        platform = None
        identifier = None

        arg_iter = iter(args)
        for arg in arg_iter:
            if arg in {"-w", "--workspace", "-p", "--platform"}:
                value = next(arg_iter, None)
                if value is None:
                    warning("Usage: sessions -H [-w workspace] [-p platform] [session_id]")
                    return None
                if arg in {"-w", "--workspace"}:
                    workspace = value
                else:
                    platform = value
            elif arg in {"-h", "--help"}:
                info("Usage: sessions -H [session_id] [-w workspace] [-p platform]")
                return None
            elif arg.startswith("-"):
                warning(f"Unknown history option: {arg}")
                return None
            elif identifier is None:
                identifier = arg
            else:
                warning("Only one historical session ID may be specified.")
                return None

        return workspace, platform, identifier

    def _show_history_record(self, identifier, workspace):
        """Print one persisted session record."""
        try:
            record = history.get_record(identifier, workspace)
        except ValueError as exc:
            error(str(exc))
            return
        if record is None:
            error(f"No historical session {identifier!r} in workspace {workspace!r}.")
            return

        self._print_history_record(record)

    def _list_history_records(self, workspace, platform):
        """Print a table of persisted session records."""
        try:
            records = history.list_records(workspace, platform)
        except ValueError as exc:
            error(str(exc))
            return
        if not records:
            info(f"No session history found in workspace {workspace!r}.")
            return

        print_line("\nSession History\n===============\n")

        rows = [
            (
                record.session_id,
                f"{record.address}:{record.port}" if record.port is not None else record.address,
                record.platform,
                record.handler,
                record.opened_at_human or str(record.opened_at),
            )
            for record in records
        ]

        tbl.render_table(
            ("Id", "Target", "Platform", "Handler", "Opened (UTC)"),
            rows,
            min_widths=[10, 12, 8, 8, 19],
            padding=3,
        )
        print_line()

    def _print_history_record(self, record):
        """Display the metadata stored for one historical session."""
        remote = f"{record.address}:{record.port}" if record.port is not None else record.address

        print_line(f"\nSession History: {record.session_id}\n" + "=" * (17 + len(record.session_id)))

        print_line("\nGeneral\n-------")
        print_line(f"Opened At    : {record.opened_at_human or record.opened_at}")
        print_line(f"Platform     : {record.platform}")
        print_line(f"Handler      : {record.handler}")
        print_line(f"Workspace    : {record.workspace}")
        print_line(f"Remote Addr  : {remote}")

        print_line("\nExploitation\n------------")
        print_line(f"Module       : {record.module or '(unknown)'}")
        print_line(f"Payload      : {record.payload or '(unknown)'}")

        print_line("\n\nExploit Options\n---------------\n")
        if not record.options:
            print_line("(no options recorded)")
            return

        # Rows
        rows = [(str(name), str(value)) for name, value in record.options.items()]

        # Render table for exploit options
        tbl.render_table(("Option", "Value"), rows, min_widths=[12, 8], padding=3)
        print_line("\n")

    def _run_session_command(self, args):
        """Handle 'sessions -C <session_id> <command>'."""
        if len(args) < 2:
            warning("Usage: sessions -C <session_id> <command>")
            return

        sid = args[0]
        session = all_sessions().get(sid)
        if session is None:
            error(f"No session with ID '{sid}'.")
            return
        if not session.runtime.alive:
            error(f"Session {sid} is dead.")
            return

        cmd_str = " ".join(args[1:])
        try:
            session.send_command(cmd_str)
            output = session.read_output(timeout=10.0)
            print_line(output.rstrip() if output else "(no output)")
        except (OSError, AttributeError) as exc:
            error(f"Session command failed: {exc}")

    def _print_sessions_table(self, sessions):
        """Render the sessions table body with automatic wrapping."""
        now = time.time()
        rows = []
        for sid, sess in sessions.items():
            age = int(now - sess.runtime.opened_at)
            status = f"{GREEN}alive{RESET}" if sess.runtime.alive else f"{RED}dead{RESET}"
            rows.append((sid, sess.transport.addr[0], sess.platform, f"{status} {age}s ago"))

        print_line("Sessions")
        print_line("========\n")

        tbl.render_table(
            ("Id", "Target", "Platform", "Opened"),
            rows,
            min_widths=[2, 10, 8, 8],
            padding=3,
        )

    def cmd_kill(self, args):
        """Gracefully close a session or stop a running job."""
        if not args:
            warning("Usage: kill <session_id | job_id> | kill all")
            return

        target = args[0].lower()
        if target == "all":
            sessions = all_sessions()
            if not sessions:
                info("No open sessions to kill.")
                return

            for sid, sess in list(sessions.items()):
                self._kill_session(sid, sess)

            success("All sessions closed.")
            return

        sessions = all_sessions()
        if target in sessions:
            self._kill_session(target, sessions[target])
            return

        killed = self.console.thread_handler.kill_task(target)
        if killed:
            success(f"Job {target[:8]} signalled to stop - listener shut down.")
            return

        error(f"No session or job matching {target!r}. Use 'sessions' or 'jobs' to list active IDs.")

    @staticmethod
    def _kill_session(session_id, session):
        """Close a session socket gracefully and remove it from the registry."""
        with contextlib.suppress(Exception):
            session.close()

        remove_session(session_id)
        addr = session.transport.addr

        success(f"Session {session_id} ({addr[0]}:{addr[1]}) closed.")

    def cmd_interact(self, args):
        """Attach to an open session and launch the shell."""
        if not args:
            warning("Usage: interact <session_id> [platform]")
            self.cmd_sessions([])
            return

        session_id = args[0]
        platform = args[1] if len(args) > 1 else None

        session = get_session(session_id)
        if session is None:
            error(f"No session with ID {session_id!r}.")
            info("Use 'sessions' to list open sessions.")
            return
        if not session.runtime.alive:
            error(f"Session {session_id} is no longer alive.")
            return

        effective_platform = platform or session.platform or "generic"
        effective_handler = getattr(session.transport, "handler", "reverse_tcp") or "reverse_tcp"

        info(
            f"Starting {effective_platform}/{effective_handler} shell on session "
            f"{session_id} ({session.transport.addr[0]}:{session.transport.addr[1]})..."
        )

        open_shell(
            session=session,
            platform=effective_platform,
            session_registry_fn=all_sessions,
            loot_manager=self.console.loot,
        )

    def cmd_jobs(self, args):
        """Display background jobs or clear completed ones."""
        if args and args[0].lower() == "clear":
            removed = self.console.thread_handler.clear_completed()
            success(f"Cleared {removed} completed job(s).")
            return

        tasks = self.console.thread_handler.all_tasks()
        if not tasks:
            info("No jobs.")
            return

        print_line()
        self._print_jobs_table(tasks)
        print_line("\n")

    def _print_jobs_table(self, tasks):
        """Render the jobs table body with automatic wrapping."""
        rows = []
        for task_id, task_info in tasks.items():
            status = task_info["status"]
            color = JOB_STATUS_COLORS.get(status, RESET)
            rows.append((task_id[:8], f"{color}{status}{RESET}"))

        print_line("Jobs")
        print_line("====\n")

        tbl.render_table(
            ("Id", "Status"),
            rows,
            min_widths=[8, 6],
            padding=3,
        )

    def flush_job_output(self):
        """Print all pending background-job events to the console."""
        level_handlers = {
            "success": success,
            "error": error,
            "warning": warning,
            "debug": debug,
            "print_line": print_line,
        }

        for event in self.console.thread_handler.output_bus.drain():
            level = event.get("level", "info")
            message = event.get("message", "")
            handler = level_handlers.get(level, info)
            handler(message)
