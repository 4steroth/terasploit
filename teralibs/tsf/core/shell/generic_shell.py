import base64
import os

from teralibs.terasploit.framework.services.printf import error, info, success, warning
from teralibs.tsf.base.shell.base import BaseShell
from teralibs.tsf.utils.exception import TerasploitShellError


class GenericShell(BaseShell):
    """
    Platform-agnostic shell for TCP sessions.

    Provides upload and download over Base64 and forwards all other input
    verbatim.  UnixShell and WindowsShell inherit from this class and add
    command translation and platform-specific upload/download strategies.
    """

    PLATFORM_LABEL = "Generic"

    # Input dispatch

    def _handle_user_input(self, raw):
        """
        Intercept upload/download commands; pass everything else to BaseShell.

        Subclasses that need platform-specific upload/download override
        _cmd_upload and _cmd_download — they do not need to re-implement
        this dispatch.
        """
        if not raw:
            return

        parts = raw.split()
        command = parts[0].lower()
        args = parts[1:]

        if command == "upload":
            self._cmd_upload(args)
        elif command == "download":
            self._cmd_download(args)
        else:
            super()._handle_user_input(raw)

    # Upload / download — generic (Unix-compatible) implementations

    def _cmd_upload(self, args):
        """
        Upload a local file to the target by piping Base64 through the shell.

        Works on any target with base64(1) available (all modern Unix systems).
        WindowsShell overrides this with a PowerShell-based chunked strategy.
        """
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

    def _cmd_download(self, args):
        """
        Download a file from the target by reading its Base64-encoded output.

        Works on any target with base64(1) available.
        WindowsShell overrides this with a PowerShell-based strategy.
        """
        if not args:
            warning("Usage: download <remote_path> [local_path]")
            return

        remote_path = args[0]
        local_path = args[1] if len(args) > 1 else os.path.basename(remote_path)

        info(f"Initiating download: {remote_path} → {local_path}")

        if not self._start_transfer(local_path):
            return

        safe_remote = remote_path.replace("'", "'\\''")
        cmd = f"base64 '{safe_remote}' 2>/dev/null; echo '---TERASPLOIT_SHELL_EOF---'"
        self._send(cmd)

    # Help

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
