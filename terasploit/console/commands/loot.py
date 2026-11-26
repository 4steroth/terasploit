import sqlite3

from terasploit.ui import tables as tbl
from terasploit.ui.printf import (
    error,
    info,
    print_line,
    success,
    warning,
)


class LootCommands:
    """Browse, inspect, export, and remove collected artifacts."""

    LOOT_USAGE = "Usage: loot [-l] [-w workspace] [-H host] [-S session] | -i <id> | -e <id> <path> | -d <id>"

    def __init__(self, console):
        self.console = console
        self.loot = console.loot

    @staticmethod
    def _loot_set_workspace(values, state):
        """Handle -w/--workspace: consume one value, store it, or return an error message."""
        state["workspace"] = next(values, None)
        if not state["workspace"]:
            return "A workspace name is required after -w."
        return None

    @staticmethod
    def _loot_set_host(values, state):
        """Handle -H/--host: consume one value, store it, or return an error message."""
        state["host"] = next(values, None)
        if not state["host"]:
            return "A host address or ID is required after -H."
        return None

    @staticmethod
    def _loot_set_session(values, state):
        """Handle -S/--session: consume one value, store it, or return an error message."""
        state["session_id"] = next(values, None)
        if not state["session_id"]:
            return "A session ID is required after -S."
        return None

    @staticmethod
    def _loot_set_info(values, state):
        """Handle -i/--info: consume one loot ID, store it, or return an error message."""
        state["identifier"] = next(values, None)
        if not state["identifier"]:
            return "A loot ID is required after -i."
        return None

    @staticmethod
    def _loot_set_export(values, state):
        """Handle -e/--export: consume id + destination path, or return an error message."""
        state["identifier"] = next(values, None)
        state["export_path"] = next(values, None)
        if not state["identifier"] or not state["export_path"]:
            return "Usage: loot -e <id> <destination>"
        return None

    @staticmethod
    def _loot_set_delete(values, state):
        """Handle -d/--delete: consume one loot ID and mark it for deletion."""
        state["identifier"] = next(values, None)
        state["delete"] = True
        if not state["identifier"]:
            return "A loot ID is required after -d."
        return None

    @staticmethod
    def _loot_noop():
        """Handle -l/--list: no value to consume, listing is the default action."""
        return None

    def cmd_loot(self, args):
        """List or manage collected artifacts in a workspace."""
        parsed = self._parse_loot_args(args, self.loot.workspace)
        if parsed is None:
            return

        workspace, host, session_id, identifier, export_path, delete = parsed
        if identifier is not None:
            if host is not None or session_id is not None:
                warning("Artifact actions cannot be combined with host or session filters.")
                return
            if export_path is not None:
                self._export(identifier, export_path, workspace)
            elif delete:
                self._delete(identifier, workspace)
            else:
                self._show(identifier, workspace)
            return

        self.list_artifacts(workspace, host, session_id)

    def _parse_loot_args(self, args, workspace):
        """Parse `loot` arguments using a flag -> handler dispatch table."""
        handlers = {
            "-w": self._loot_set_workspace,
            "--workspace": self._loot_set_workspace,
            "-H": self._loot_set_host,
            "--host": self._loot_set_host,
            "-S": self._loot_set_session,
            "--session": self._loot_set_session,
            "-i": self._loot_set_info,
            "--info": self._loot_set_info,
            "-e": self._loot_set_export,
            "--export": self._loot_set_export,
            "-d": self._loot_set_delete,
            "--delete": self._loot_set_delete,
            "-l": self._loot_noop,
            "--list": self._loot_noop,
        }
        state = {
            "workspace": workspace,
            "host": None,
            "session_id": None,
            "identifier": None,
            "export_path": None,
            "delete": False,
        }
        values = iter(args)
        for arg in values:
            if arg in {"-h", "--help"}:
                info(self.LOOT_USAGE)
                return None

            handler = handlers.get(arg)
            if handler is None:
                warning(f"Unknown loot argument: {arg}")
                info(self.LOOT_USAGE)
                return None

            error_message = handler(values, state)
            if error_message is not None:
                warning(error_message)
                return None

        return (
            state["workspace"],
            state["host"],
            state["session_id"],
            state["identifier"],
            state["export_path"],
            state["delete"],
        )

    def list_artifacts(self, workspace, host=None, session_id=None):
        """Display cataloged artifacts with optional host or session filters."""
        try:
            records = self.loot.get_all(workspace=workspace, host=host, session_id=session_id)
        except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
            error(f"Unable to list loot: {exc}")
            return

        print_line(f"\nLoot - Workspace: {workspace}\n==================" + "=" * len(workspace) + "\n")
        if not records:
            info("No artifacts found.")
            return

        rows = [
            (
                row["id"],
                row["filename"],
                row["host"] or ".",
                row["session_id"] or ".",
                self._format_size(row["size"]),
                row["source"],
                row["created_at"],
            )
            for row in records
        ]
        rows.sort()

        tbl.render_table(
            ("ID", "Name", "Host", "Session", "Size", "Source", "Collected"),
            rows,
            min_widths=[2, 10, 7, 9, 6, 6, 19],
            padding=2,
        )
        print_line()

    def _show(self, identifier, workspace):
        """Display all metadata for one artifact."""
        try:
            record = self.loot.get_artifact(identifier, workspace=workspace)
        except sqlite3.Error as exc:
            error(f"Unable to retrieve loot: {exc}")
            return
        if record is None:
            error(f"Loot record {identifier!r} was not found in workspace {workspace!r}.")
            return

        print_line(f"\nLoot Record: {record['id']}\n=============" + "=" * len(str(record["id"])) + "\n")
        for label, value in (
            ("Filename", record["filename"]),
            ("Workspace", workspace),
            ("Host", record["host"] or "-"),
            ("Session", record["session_id"] or "-"),
            ("Platform", record["platform"] or "-"),
            ("Source", record["source"]),
            ("Module", record["module"] or "-"),
            ("Content Type", record["content_type"]),
            ("Size", f"{record['size']:,} bytes"),
            ("SHA-256", record["sha256"]),
            ("Collected", record["created_at"]),
            ("Stored At", self.loot.path_for(record)),
            ("Description", record["description"] or "-"),
        ):
            print_line(f"{label:<16}: {value}")
        print_line("\n")

    def _export(self, identifier, destination, workspace):
        """Export a stored artifact to a user-selected path."""
        try:
            path = self.loot.export(identifier, destination, workspace=workspace)
        except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
            error(f"Unable to export loot: {exc}")
            return
        success(f"Loot {identifier} exported to {path}")

    def _delete(self, identifier, workspace):
        """Delete an artifact and its catalog entry."""
        try:
            removed = self.loot.delete(identifier, workspace=workspace)
        except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
            error(f"Unable to delete loot: {exc}")
            return
        if removed:
            success(f"Loot {identifier} deleted.")
        else:
            error(f"Loot record {identifier!r} was not found in workspace {workspace!r}.")

    @staticmethod
    def _format_size(size):
        """Format a byte count using a readable binary unit."""
        value = float(size)
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if unit == "B":
                if value < 1024:
                    return f"{int(value)} B"
            elif value < 1024 or unit == "TiB":
                return f"{value:.1f} {unit}"
            value /= 1024
        return None  # unreachable: TiB branch above always returns
