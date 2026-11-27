from extension.shell.generic import GenericShell


class UnixShell(GenericShell):
    """Unix interactive shell for TCP sessions."""

    PLATFORM_LABEL = "Unix"

    def _build_loot_cmd(self, remote_cmd: str) -> str:
        safe_cmd = remote_cmd.replace("'", "'\\''")
        return f"printf '%s%s\\n' '---TERASPLOIT_' 'SHELL_SOF---'; ( {safe_cmd} ) 2>&1 | base64; printf '%s%s\\n' '---TERASPLOIT_' 'SHELL_EOF---'"
