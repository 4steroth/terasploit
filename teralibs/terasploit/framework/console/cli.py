import contextlib
import os
import shlex
import subprocess
import time

from teralibs.terasploit.framework.console.help import help_sections
from teralibs.terasploit.framework.console.helpers import _to_path
from teralibs.terasploit.framework.console.loaders import ConsoleLoader
from teralibs.terasploit.framework.console.show import ConsoleRenderer
from teralibs.terasploit.framework.console.terasploit import Terasploit
from teralibs.terasploit.framework.encoder.factory_reset import reset_encoder_factory
from teralibs.terasploit.framework.exploit.driver import (
    DriverDeps,
    ExploitDriver,
    all_sessions,
    get_session,
    remove_session,
)
from teralibs.terasploit.framework.exploit.entry import open_shell
from teralibs.terasploit.framework.payload.badchar_filter import parse_badchars
from teralibs.terasploit.framework.services import tables as tbl
from teralibs.terasploit.framework.services.banner import display_banner
from teralibs.terasploit.framework.services.printf import (
    BOLD,
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
from teralibs.tsf.core.module.context import (
    AuxiliaryContext,
    AuxiliaryContextDeps,
    ExploitContext,
    ExploitContextDeps,
    PostContext,
    PostContextDeps,
)
from teralibs.tsf.utils.exception import ShellExecError


# Command alias sets
_EXIT_ALIASES = frozenset({"exit", "quit", "q", "close", "terminate"})
_RUN_ALIASES = frozenset({"run", "exploit", "execute"})


class CLi(ConsoleLoader, ConsoleRenderer, Terasploit):
    """Interactive Terasploit console."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Give the tables module access to the module index so it can
        # load metadata while rendering the modules table.
        tbl.set_module_index(self.modules)

    # REPL helpers

    def _user_prompt(self):
        """Build the context-sensitive prompt string."""
        label = self.datastore.get("PROMPT", scope="framework")
        char = self.datastore.get("PROMPT_CHAR", scope="framework")

        entry = self.module_storage.module()

        if entry is None:
            return f"\001\033[4m\002{label}\001{RESET}\002 {char} "

        display = _to_path(entry.name)
        return f"\001\033[4m\002{label}\001{RESET}\002 (\001{BOLD}\002\001{RED}\002{display}\001{RESET}\002) {char} "

    def parse_line(self, line):
        """
        Returns a (command, args) pair where command is the first token
        lowercased and args is the remaining token list.
        """
        stripped = line.strip()

        if not stripped:
            return "", []

        try:
            tokens = shlex.split(stripped)
        except ValueError as exc:
            raise RuntimeError(f"Parse error: {exc}") from exc

        return tokens[0].lower(), tokens[1:]

    def dispatch(self, command, args):
        """Route a command to its _cmd_* handler method."""
        if command in _EXIT_ALIASES:
            self.shutdown()
            return

        if command in _RUN_ALIASES:
            command = "run"

        if command == "?":
            command = "help"

        if command in ("session",):
            command = "sessions"

        if command in ("i",):
            command = "interact"

        if command in ("k",):
            command = "kill"

        handler = getattr(self, f"_cmd_{command}", None)
        if handler:
            debug(f"dispatch -> {command} {args}")
            handler(args)
            return

        warning(f"Unknown command: '{command}'.  Type 'help' for a list.")

    # Top-level command handlers

    def _cmd_banner(self, _):
        """Display the terasploit framework banner."""
        display_banner(self.modules.list())

    def _cmd_help(self, _):
        """Display a grouped command reference table."""
        print_line()

        for section_name, entries in help_sections:
            print_line(f"{section_name} commands\n")
            print_line(f"   {'Command':<30}  Description")
            print_line(f"   {'-------':<30}  -----------")

            for cmd, desc in entries:
                print_line(f"   {cmd:<30}  {desc}")
            print_line("\n")

    def _cmd_clear(self, _):
        """Clear the terminal screen using the appropriate platform command."""
        if os.name == "nt":
            subprocess.run(["cls"], shell=True, check=False)
        else:
            subprocess.run(["clear"], shell=True, check=False)

    def _cmd_exec(self, args):
        """Execute a system shell command and stream its output to the console."""
        if not args:
            warning("Usage: exec <command>  (example: exec whoami)")
            return

        command_string = " ".join(args)

        info(f"Executing: {command_string}")
        print_line()

        try:
            # shell=True is intentional - see docstring above.
            process = subprocess.run(
                command_string,
                shell=True,
                check=False,
            )
            print_line()
            if process.returncode != 0:
                warning(f"Command exited with status {process.returncode}.")

        except ShellExecError as exc:
            error(f"Shell execution failed: {exc}")

    def _cmd_reload(self, _):
        """Force-rescan the module index and reset the encoder registry."""
        self.modules.refresh(force=True)
        reset_encoder_factory()
        count = len(self.modules)
        success(f"Module index refreshed - {count} module(s) indexed.")

    def _cmd_search(self, args):
        """Search the module index and display results in a table."""
        if not args:
            warning("Usage: search <query> [more words...]")
            return

        query = " ".join(args)
        fuzzy = len(args) > 1
        results = self.modules.search(query, fuzzy=fuzzy)

        if not results:
            warning(f"No modules matching '{query}'.")
            return

        print_line(f'\nSearch: "{query}"\n')
        tbl.modules_table(results)

        # Guide for users.
        print_line(
            "\n\nInteract with a module by path using",
            f"the command '{GREEN}use <module_path>{RESET}'\n",
        )

    def _cmd_info(self, args):
        """Display metadata for the active module or a named one."""
        if args:
            name = args[0].replace("/", ".")
            mod = self.modules.load(name)

            if mod is None:
                error(f"Module not found: {args[0]!r}")
                return

            obj = getattr(mod, "TerasploitModule", None)

            if obj is None:
                error(f"Module {args[0]!r} has no TerasploitModule class.")
                return

        else:
            entry = self.module_storage.module()

            if entry is None:
                warning("No module loaded.  Run 'info <module>' or load one first.")
                return

            obj = type(entry.module)
            name = entry.name

        print_line()

        meta_fields = [
            ("Name", "NAME"),
            ("Module", None),
            ("Platform", "PLATFORM"),
            ("Arch", "ARCH"),
            ("Rank", "RANK"),
            ("Description", "DESCRIPTION"),
            ("Author", "AUTHOR"),
            ("License", "LICENSE"),
            ("References", "REFERENCES"),
        ]

        for label, attribute in meta_fields:
            if attribute is None:
                print_line(f"   {BOLD}{label}:{RESET} {_to_path(name)}")
                continue

            value = getattr(obj, attribute, None)

            if value is None:
                continue

            if isinstance(value, (list, tuple)) and value:
                print_line(f"   {BOLD}{label}:{RESET}")
                for item in value:  # pylint: disable=not-an-iterable
                    print_line(f"      {item}")

            elif value:
                # Scalar values (str, int, Enum, etc.) - render on one line.
                print_line(f"   {BOLD}{label}:{RESET} {value}")

        print_line()

    # Execution

    def _cmd_generate(self, args):
        """Generate a NOP sled from the active NOP module."""
        entry = self.module_storage.module()
        if entry is None:
            warning("No module loaded.  Use 'use <module>' first.")
            return

        if not entry.name.startswith("nop"):
            warning(f"'{_to_path(entry.name)}' is not a NOP module.  Load a nop/* module first.")
            return

        sled_size = 0
        badchars: frozenset[int] = frozenset()

        i = 0
        while i < len(args):
            token = args[i]
            if token == "-b" and i + 1 < len(args):
                i += 1
                try:
                    badchars = parse_badchars(args[i])
                except ValueError as exc:
                    error(f"Invalid badchars: {exc}")
                    return
            else:
                try:
                    sled_size = int(token)
                except ValueError:
                    error(f"Invalid size argument: {token!r}  (expected an integer)")
                    return
            i += 1

        # Fall back to datastore NopSledSize when no size was passed.
        if sled_size <= 0:
            raw = self.datastore.get("NopSledSize") or "0"
            try:
                sled_size = int(raw)
            except TypeError, ValueError:
                sled_size = 0

        if sled_size <= 0:
            error("No size specified.  Pass a size argument or set NopSledSize.")
            return

        self._generate_nops_sled(entry, sled_size, badchars)

    def _generate_nops_sled(self, entry, sled_size, badchars):
        """Generate no-operation sled."""

        # Fall back to datastore BADCHARS when -b was not passed.
        if not badchars:
            raw_bc = self.datastore.get("BADCHARS") or ""
            if raw_bc:
                with contextlib.suppress(ValueError):
                    badchars = parse_badchars(raw_bc)

        result = entry.module.generate(sled_size, badchars)

        if not result.success:
            error(f"[NopSled] Generation failed: {result.error}")
            return

        sled = result.sled_bytes
        info(f"NOP sled: {len(sled):,} bytes via '{result.nop_name}'" + (f" (avoiding {len(badchars)} bad byte(s))" if badchars else ""))

        # Hex dump output - 16 bytes per row with printable-char column.
        print_line()
        for offset in range(0, len(sled), 16):
            chunk = sled[offset : offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)

            print_line(f"  {offset:04x}  {hex_part:<47}  {asc_part}")

        print_line()
        success(f"Generated {len(sled):,}-byte NOP sled.")

    def _cmd_check(self, _):
        """Probe the target for vulnerability without launching the full exploit."""
        entry = self.module_storage.module()
        if entry is None:
            warning("No module loaded.  Use 'use <module>' first.")
            return

        if not hasattr(entry.module, "check"):
            warning(f"{entry.name} does not implement a check() method. Run 'run' to execute the full exploit.")
            return

        is_exploit = entry.name.startswith("exploit")

        # Payload only relevant for exploit modules
        payload_entry = None
        payload_obj = None

        if is_exploit is True:
            payload_entry = self.module_storage.payload() or self.module_storage.module()

            # The payload object
            payload_obj = payload_entry.module if payload_entry is not None else None

        missing = (
            self.datastore.missing_required("module") + self.datastore.missing_required("payload")
            if is_exploit
            else self.datastore.missing_required("module")
        )
        if missing:
            error(f"Required option(s) not set: {RED}{', '.join(missing)}{RESET}.")
            return

        if is_exploit:

            def _run_exploit(worker_ctx):
                _ctx = ExploitContext(
                    ExploitContextDeps(
                        job_id=worker_ctx.job_id,
                        module_obj=entry.module,
                        payload_obj=payload_obj,
                        datastore=self.datastore,
                        bus=worker_ctx.bus,
                    )
                )
                entry.module.check(_ctx)

            driver = _run_exploit
        else:

            def _run_auxiliary(worker_ctx):
                _ctx = AuxiliaryContext(
                    AuxiliaryContextDeps(
                        job_id=worker_ctx.job_id,
                        bus=worker_ctx.bus,
                        datastore=self.datastore,
                    )
                )
                entry.module.run(_ctx)

            driver = _run_auxiliary

        try:
            task_id = self.thread_handler.submit(driver)

        except (ValueError, OSError) as exc:
            error(f"Driver error: {exc}")

            if isinstance(driver, ExploitDriver):
                if hasattr(driver, "stop"):
                    driver.stop()
                else:
                    warning("Driver has no stop() method - cannot clean up.")
            return

        self._async_job_runner(task_id)

    def _cmd_run(self, _):
        """Execute the active module and block until it finishes."""
        entry = self.module_storage.module()

        if entry is None:
            warning("No module loaded.  Use 'use <module>' first.")
            return

        is_nop = entry.name.startswith("nop")
        # Nop modules are not executed via run - they generate sleds.
        # Redirect the user to the generate command.
        if is_nop:
            warning(f"'{_to_path(entry.name)}' is a NOP module - use 'generate' to produce a sled.")
            return

        # Run post module
        is_post = entry.name.startswith("post")
        if is_post is True:
            self._run_post_module()
            return

        is_exploit = entry.name.startswith("exploit") or entry.name.startswith("payload") or entry.name.startswith("evasion")

        missing = (
            self.datastore.missing_required("module") + self.datastore.missing_required("payload")
            if is_exploit
            else self.datastore.missing_required("module")
        )
        if missing:
            error(f"Required option(s) not set: {RED}{', '.join(missing)}{RESET}.")
            return

        # Payload only relevant for exploit modules
        payload_entry = None
        payload_obj = None

        if is_exploit is True:
            # Since we can import payloads as well, we will get the payload entry
            # to module_storage.module() as well.
            payload_entry = self.module_storage.payload() or self.module_storage.module()

            # The payload object
            payload_obj = payload_entry.module if payload_entry is not None else None

        if not hasattr(entry.module, "run"):
            warning(f"Module '{_to_path(entry.name)}' has no 'run' method.")
            return

        # Execute the module
        self._run_module(entry, is_exploit, payload_obj)

    def _run_module(self, entry, is_exploit, payload_obj):
        """Execute auxiliary/exploit modules."""

        debug(f"Running module: {_to_path(entry.name)}")
        driver = None
        if is_exploit is True:
            driver = ExploitDriver(
                DriverDeps(
                    module_obj=entry.module,
                    payload_obj=payload_obj,
                    datastore=self.datastore,
                    thread_handler=self.thread_handler,
                    output_bus=self.thread_handler.output_bus,
                    session_callback=self._on_session_opened,
                )
            )
        else:

            def _run_auxiliary(worker_ctx):
                _ctx = AuxiliaryContext(
                    AuxiliaryContextDeps(
                        job_id=worker_ctx.job_id,
                        bus=worker_ctx.bus,
                        datastore=self.datastore,
                    )
                )
                if entry and hasattr(entry, "module"):
                    entry.module.run(_ctx)
                else:
                    error("Module has no 'run' method.")

            driver = _run_auxiliary
        try:
            task_id = driver.run() if isinstance(driver, ExploitDriver) and is_exploit and driver is not None else self.thread_handler.submit(driver)

        except (ValueError, OSError) as exc:
            error(f"Driver error: {exc}")

            if isinstance(driver, ExploitDriver):
                if hasattr(driver, "stop"):
                    driver.stop()
                else:
                    warning("Driver has no stop() method - cannot clean up.")
            return

        self._async_job_runner(task_id)

    def _run_post_module(self):
        """
        Running post module gets a standalone method because it is
        different to auxiliary and exploit context.
        """
        session_id = self.datastore.get("SESSION")
        session = get_session(session_id) if session_id else None

        entry = self.module_storage.module()

        if session is None:
            error(f"Session {session_id!r} not found. Use 'sessions' to list open sessions.")
            return

        if not session.runtime.alive:
            error(f"Session {session_id!r} is no longer alive.")
            return

        def _run_post(worker_ctx):
            post_ctx = PostContext(
                PostContextDeps(
                    job_id=worker_ctx.job_id,
                    bus=worker_ctx.bus,
                    datastore=self.datastore,
                    session=session,
                )
            )
            if entry and hasattr(entry, "module"):
                entry.module.run(post_ctx)
            else:
                error("Module has no 'run' method.")

        try:
            task_id = self.thread_handler.submit(_run_post)
        except (ValueError, OSError) as exc:
            error(f"Post module error: {exc}")
            return

        self._async_job_runner(task_id)

    def _async_job_runner(self, task_id):
        """Acts as the "Standard Output (Stdout) Proxy"""
        try:
            while not self.thread_handler.wait_until_done(task_id, poll=0.15):
                if self.thread_handler.output_bus.pending() > 0:
                    self._flush_job_output()

        except KeyboardInterrupt:
            print_line()
            warning("Interrupt - killing job.")
            self.thread_handler.kill_task(task_id)
            while not self.thread_handler.wait_until_done(task_id, poll=0.15):
                try:
                    if self.thread_handler.output_bus.pending() > 0:
                        self._flush_job_output()

                # We ignore any ctrl+c coming. You executed it, finish it.
                except KeyboardInterrupt:
                    continue

        # Final drain so the last events (session opened, errors) are visible.
        self._flush_job_output()

    def _on_session_opened(self, session):
        """Called by the ExploitDriver when a new session is established."""

        session_id = session.session_id
        addr = session.transport.addr

        self.thread_handler.output_bus.emit("session", "success", f"Session {session_id} opened ({addr[0]}:{addr[1]})")

    # Session management

    def _cmd_sessions(self, args):
        """List all currently open Shell Sessions."""
        # Handle sessions -C <id> <command>
        if args and args[0] == "-C":
            if len(args) < 3:
                warning("Usage: sessions -C <session_id> <command>")
                return
            sid = args[1]
            cmd_str = " ".join(args[2:])
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
            return

        sessions = all_sessions()
        print_line()

        if not sessions:
            info("No open sessions.")
            print_line()
            return

        w_id = max(len("Id"), max(len(s.session_id) for s in sessions.values()))
        w_host = max(len("Target"), max(len(s.transport.addr[0]) for s in sessions.values()))
        w_platform = max(len("Platform"), max(len(s.platform) for s in sessions.values()))

        # Header
        print_line("Sessions")
        print_line("========\n")

        # Table header
        print_line(f"   {'Id':<{w_id}}  {'Target':<{w_host}}  {'Platform':<{w_platform}}  Opened")
        print_line(f"   {'-' * 2:<{w_id}}  {'-' * 6:<{w_host}}  {'-' * 8:<{w_platform}}  {'-' * 6}")

        now = time.time()
        for sid, sess in sessions.items():
            age = int(now - sess.runtime.opened_at)
            status = f"{GREEN}alive{RESET}" if sess.runtime.alive else f"{RED}dead{RESET}"
            print_line(f"   {sid:<{w_id}}  {sess.transport.addr[0]:<{w_host}}  {sess.platform:<{w_platform}}  {status} {age}s ago")

        print_line("\n\nUse 'interact <id>' to attach, or 'sessions -C <id> <cmd>' to run a single command.")
        print_line()

    def _cmd_kill(self, args):
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
                self._kill_session(sid, sess, remove_session)
            success("All sessions closed.")
            return

        sessions = all_sessions()
        if target in sessions:
            self._kill_session(target, sessions[target], remove_session)
            return

        killed = self.thread_handler.kill_task(target)
        if killed:
            success(f"Job {target[:8]} signalled to stop - listener shut down.")
            return

        error(f"No session or job matching {target!r}.  Use 'sessions' or 'jobs' to list active IDs.")

    @staticmethod
    def _kill_session(session_id, session, remove_fn):
        """Close a session socket gracefully and remove it from the registry."""
        with contextlib.suppress(Exception):
            session.close()

        remove_fn(session_id)

        addr = session.transport.addr
        success(f"Session {session_id} ({addr[0]}:{addr[1]}) closed.")

    def _cmd_interact(self, args):
        """Attach to an open session and launch the shell."""
        if not args:
            warning("Usage: interact <session_id> [platform]")
            self._cmd_sessions([])
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

    # Jobs

    def _cmd_jobs(self, args):
        """Display background jobs or clear completed ones."""
        if args and args[0].lower() == "clear":
            removed = self.thread_handler.clear_completed()
            success(f"Cleared {removed} completed job(s).")
            return

        tasks = self.thread_handler.all_tasks()

        print_line()
        if not tasks:
            info("No jobs.")
            print_line()
            return

        status_colors = {
            "queued": YELLOW,
            "running": CYAN,
            "completed": GREEN,
            "failed": RED,
            "killed": RED,
        }

        # Header
        print_line("Jobs")
        print_line("====\n")

        # Table header
        print_line(f"   {'Id':<8}  Status")
        print_line(f"   {'-' * 2:<8}  {'-' * 6}")

        for task_id, task_info in tasks.items():
            status = task_info["status"]
            color = status_colors.get(status, RESET)
            short_id = task_id[:8]
            print_line(f"   {short_id:<8}  {color}{status}{RESET}")

        print_line("\n")

    # REPL entry point

    def start(self):
        """Enter the interactive read-eval loop."""
        while self.console_toggle:
            if self.thread_handler.output_bus.pending() > 0:
                self._flush_job_output()

            try:
                raw = input(self._user_prompt()).strip()
            except KeyboardInterrupt:
                print_line()
                warning("Interrupt received.  Type 'exit' to quit.")
                continue
            except EOFError:
                print_line()
                error("EOF received - shutting down.")
                self.shutdown()
                break

            try:
                command, args = self.parse_line(raw)
            except RuntimeError as exc:
                error(str(exc))
                continue

            if not command:
                continue

            self.dispatch(command, args)

    def _flush_job_output(self):
        """Print all pending background-job events to the console."""
        level_handlers = {
            "success": success,
            "error": error,
            "warning": warning,
        }

        for event in self.thread_handler.output_bus.drain():
            level = event.get("level", "info")
            message = event.get("message", "")
            handler = level_handlers.get(level, info)
            handler(message)
