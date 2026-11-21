import contextlib
import time

from teralibs.terasploit.framework.console.base import BaseConsole
from teralibs.terasploit.framework.exploit.driver import (
    all_sessions,
    get_session,
    remove_session,
)
from teralibs.terasploit.framework.exploit.entry import open_shell
from teralibs.terasploit.framework.services.printf import (
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


def _column_width(header, values):
    """Return the minimum column width that fits the header and every value."""
    return max(len(header), max((len(v) for v in values), default=0))


class SessionsCommands:
    """Handle sessions console commands."""

    def __init__(self, console: BaseConsole) -> None:
        """Bind this command group to the shared console."""
        self.console = console

    def cmd_sessions(self, args):
        """List all currently open Shell Sessions."""
        if args and args[0] == "-C":
            self._run_session_command(args[1:])
            return

        sessions = all_sessions()
        print_line()

        if not sessions:
            info("No open sessions.")
            print_line()
            return

        self._print_sessions_table(sessions)
        print_line()

    def _run_session_command(self, args):
        """Handle 'sessions -C <session_id> <command>'."""
        if len(args) < 2:
            warning("Usage: sessions -C <session_id> <command>")
            return

        sid = args[0]
        cmd_str = " ".join(args[1:])

        session = all_sessions().get(sid)
        if session is None:
            error(f"No session with ID '{sid}'.")
            return

        if not session.runtime.alive:
            error(f"Session {sid} is dead.")
            return

        try:
            session.send_command(cmd_str)
            output = session.read_output(timeout=10.0)
            print_line(output.rstrip() if output else "(no output)")

        except (OSError, AttributeError) as exc:
            error(f"Session command failed: {exc}")

    def _print_sessions_table(self, sessions):
        """Render the sessions table body."""
        w_id = _column_width("Id", (s.session_id for s in sessions.values()))
        w_host = _column_width("Target", (s.transport.addr[0] for s in sessions.values()))
        w_platform = _column_width("Platform", (s.platform for s in sessions.values()))

        print_line("Sessions")
        print_line("========\n")

        print_line(f"   {'Id':<{w_id}}  {'Target':<{w_host}}  {'Platform':<{w_platform}}  Opened")
        print_line(f"   {'-' * 2:<{w_id}}  {'-' * 6:<{w_host}}  {'-' * 8:<{w_platform}}  {'-' * 6}")

        now = time.time()
        for sid, sess in sessions.items():
            age = int(now - sess.runtime.opened_at)
            status = f"{GREEN}alive{RESET}" if sess.runtime.alive else f"{RED}dead{RESET}"
            print_line(f"   {sid:<{w_id}}  {sess.transport.addr[0]:<{w_host}}  {sess.platform:<{w_platform}}  {status} {age}s ago")

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

        error(f"No session or job matching {target!r}.  Use 'sessions' or 'jobs' to list active IDs.")

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
        )

    def cmd_jobs(self, args):
        """Display background jobs or clear completed ones."""
        if args and args[0].lower() == "clear":
            removed = self.console.thread_handler.clear_completed()
            success(f"Cleared {removed} completed job(s).")
            return

        tasks = self.console.thread_handler.all_tasks()

        print_line()
        if not tasks:
            info("No jobs.")
            print_line()
            return

        self._print_jobs_table(tasks)
        print_line("\n")

    def _print_jobs_table(self, tasks):
        """Render the jobs table body."""
        print_line("Jobs")
        print_line("====\n")

        print_line(f"   {'Id':<8}  Status")
        print_line(f"   {'-' * 2:<8}  {'-' * 6}")

        for task_id, task_info in tasks.items():
            status = task_info["status"]
            color = JOB_STATUS_COLORS.get(status, RESET)
            short_id = task_id[:8]
            print_line(f"   {short_id:<8}  {color}{status}{RESET}")

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
