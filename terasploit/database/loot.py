import sqlite3
from datetime import UTC, datetime
from pathlib import Path


class LootDatabase:
    """Store workspace-scoped metadata for collected artifacts."""

    def __init__(self, path, intelligence_database):
        self.path = Path(path)
        self.intelligence_database = intelligence_database
        self._initialize()

    def _connect(self):
        """Open a configured SQLite connection."""
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")

        return connection

    def _initialize(self):
        """Create the loot metadata schema when needed."""
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS loot (
                    id INTEGER PRIMARY KEY,
                    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    host_id INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
                    host_address TEXT,
                    session_id TEXT,
                    module TEXT,
                    source TEXT NOT NULL DEFAULT 'module',
                    filename TEXT NOT NULL,
                    relative_path TEXT NOT NULL UNIQUE,
                    content_type TEXT NOT NULL,
                    size INTEGER NOT NULL CHECK(size >= 0),
                    sha256 TEXT NOT NULL,
                    description TEXT,
                    platform TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_loot_workspace ON loot(workspace_id);
                CREATE INDEX IF NOT EXISTS idx_loot_host ON loot(host_id);
                CREATE INDEX IF NOT EXISTS idx_loot_session ON loot(session_id);
                CREATE INDEX IF NOT EXISTS idx_loot_sha256 ON loot(sha256);
                """
            )

    @staticmethod
    def _now():
        """Return the current UTC timestamp."""
        return datetime.now(UTC).isoformat(timespec="seconds")

    def add(
        self,
        *,
        workspace,
        host,
        session_id,
        module,
        source,
        filename,
        relative_path,
        content_type,
        size,
        sha256,
        description,
        platform,
    ):
        """Insert artifact metadata and return its database row."""
        workspace_id = self.intelligence_database.ensure_workspace(workspace)
        host_id = None

        host_address = str(host).strip() if host else None
        if host_address:
            host_row = self.intelligence_database.get_host(workspace, host_address)
            if host_row is not None:
                host_id = host_row["id"]

        with self._connect() as db:
            cursor = db.execute(
                """
                INSERT INTO loot(
                    workspace_id, host_id, host_address, session_id, module, source,
                    filename, relative_path, content_type, size, sha256, description,
                    platform, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    workspace_id,
                    host_id,
                    host_address,
                    str(session_id) if session_id else None,
                    str(module) if module else None,
                    str(source or "module"),
                    filename,
                    relative_path,
                    content_type,
                    int(size),
                    sha256,
                    description,
                    platform,
                    self._now(),
                ),
            )
            return db.execute(
                """
                SELECT l.*, COALESCE(h.address, l.host_address) AS host
                FROM loot l LEFT JOIN hosts h ON h.id = l.host_id
                WHERE l.id = ?
                """,
                (cursor.lastrowid,),
            ).fetchone()

    def get_all(self, workspace, *, host=None, session_id=None, limit=200):
        """Return recent artifacts in a workspace with optional filters."""
        workspace_id = self.intelligence_database.ensure_workspace(workspace)
        query = """
            SELECT l.*, COALESCE(h.address, l.host_address) AS host
            FROM loot l LEFT JOIN hosts h ON h.id = l.host_id
            WHERE l.workspace_id = ?
        """
        params = [workspace_id]
        if host is not None:
            query += " AND (l.host_address = ? OR CAST(l.host_id AS TEXT) = ?)"
            params.extend((str(host), str(host)))
        if session_id is not None:
            query += " AND l.session_id = ?"
            params.append(str(session_id))

        query += " ORDER BY l.created_at DESC, l.id DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))

        with self._connect() as db:
            return db.execute(query, params).fetchall()

    def get_artifact(self, workspace, identifier):
        """Find an artifact by catalog ID in the selected workspace."""
        workspace_id = self.intelligence_database.ensure_workspace(workspace)

        with self._connect() as db:
            return db.execute(
                """
                SELECT l.*, COALESCE(h.address, l.host_address) AS host
                FROM loot l LEFT JOIN hosts h ON h.id = l.host_id
                WHERE l.workspace_id = ? AND l.id = ?
                """,
                (workspace_id, int(identifier)),
            ).fetchone()

    def delete(self, workspace, identifier):
        """Remove an artifact's catalog entry and return its metadata."""
        workspace_id = self.intelligence_database.ensure_workspace(workspace)

        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM loot WHERE workspace_id = ? AND id = ?",
                (workspace_id, int(identifier)),
            ).fetchone()
            if row is None:
                return None

            db.execute("DELETE FROM loot WHERE id = ?", (row["id"],))
            return row
