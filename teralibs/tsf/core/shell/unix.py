from collections.abc import Mapping

from teralibs.terasploit.framework.services.printf import info
from teralibs.tsf.core.shell.generic_shell import GenericShell


class UnixShell(GenericShell):
    """
    Unix interactive shell for TCP sessions.

    Inherits upload/download and all core built-ins from GenericShell and
    adds Unix-specific command translation and a tailored help menu.
    """

    PLATFORM_LABEL = "Unix"

    # Map of Terasploit command name → Unix command sent to target.
    _UNIX_ALIASES: Mapping[str, str] = {
        "dir": "ls -la",
        "sysinfo": "uname -a && id && hostname",
        "getuid": "id",
        "getpid": "echo $$",
    }

    # Input dispatch — adds command translation before passing to GenericShell

    def _handle_user_input(self, raw):
        """Translate Unix aliases then delegate to GenericShell dispatch."""
        if not raw:
            return
        super()._handle_user_input(self._translate_command(raw))

    def _translate_command(self, raw):
        """Rewrite Terasploit-style commands to their Unix equivalents."""
        parts = raw.split(None, 1)
        verb = parts[0].lower() if parts else ""
        rest = parts[1] if len(parts) > 1 else ""

        if verb in self._UNIX_ALIASES:
            translated = self._UNIX_ALIASES[verb]
            info(f"Translated: {raw!r} → {translated!r}")
            return f"{translated} {rest}".strip() if rest else translated

        return raw

    # loot — Unix override builds a POSIX-compatible capture command

    def _build_loot_cmd(self, remote_cmd: str) -> str:
        safe_cmd = remote_cmd.replace("'", "'\\''")
        return f"( {safe_cmd} ) 2>&1 | base64; echo '---TERASPLOIT_SHELL_EOF---'"

    # Help

    def _help_sections(self) -> list:
        core, filesystem, execution = super()._help_sections()
        system = (
            "System",
            [
                ("sysinfo", "uname -a && id && hostname on target"),
                ("getuid", "id — print current user"),
                ("getpid", "echo $$ — print agent PID"),
            ],
        )
        unix_fs = (
            filesystem[0],
            filesystem[1]
            + [
                ("pwd", "Print working directory"),
                ("ls [path]", "List files (ls -la)"),
                ("dir [path]", "Alias for ls -la"),
                ("cd <path>", "Change working directory"),
                ("cat <file>", "Print file contents"),
            ],
        )
        return [core, system, unix_fs, execution]
