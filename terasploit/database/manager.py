import sqlite3
from datetime import UTC, datetime
from pathlib import Path


class IntelligenceDatabase:
    """Store workspace-scoped hosts, services, and assessment findings."""

    def __init__(self, path=None):
        """Initialize the SQLite intelligence database."""
        project_root = Path(__file__).resolve().parents[2]

        self.path = Path(path) if path else project_root / "data" / "terasploit.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self._initialize()

    def _connect(self):
        """Open a configured SQLite connection."""
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")

        return connection

    def _initialize(self):
        """Create the intelligence schema when needed."""
        with self._connect() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS workspaces (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    address TEXT NOT NULL, hostname TEXT, platform TEXT, architecture TEXT, notes TEXT,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, UNIQUE(workspace_id, address)
                );
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                    protocol TEXT NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
                    name TEXT, product TEXT, version TEXT, state TEXT NOT NULL DEFAULT 'unknown',
                    banner TEXT, observed_at TEXT NOT NULL, UNIQUE(host_id, protocol, port)
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                    title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info', status TEXT NOT NULL DEFAULT 'observed',
                    reference TEXT, description TEXT, evidence TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_hosts_workspace ON hosts(workspace_id);
                CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
                CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
                """
            )

    @staticmethod
    def _now():
        """Return the current UTC timestamp."""
        return datetime.now(UTC).isoformat(timespec="seconds")

    def ensure_workspace(self, name):
        """Create a workspace if it does not exist."""
        name = str(name).strip()
        if not name:
            raise ValueError("Workspace name cannot be empty.")

        with self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO workspaces(name, created_at) VALUES (?, ?)",
                (name, self._now()),
            )
            return db.execute(
                "SELECT id FROM workspaces WHERE name = ?",
                (name,),
            ).fetchone()["id"]

    def list_workspaces(self):
        """Return all workspaces."""
        with self._connect() as db:
            return db.execute("SELECT name, created_at FROM workspaces ORDER BY name").fetchall()

    def add_host(self, workspace, address, hostname=None, platform=None, architecture=None):
        """Insert or update a host record."""
        workspace_id = self.ensure_workspace(workspace)

        address = str(address).strip()
        if not address:
            raise ValueError("Host address cannot be empty.")

        now = self._now()
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO hosts(workspace_id,address,hostname,platform,architecture,first_seen,last_seen)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(workspace_id,address) DO UPDATE SET
                hostname=COALESCE(excluded.hostname,hosts.hostname), platform=COALESCE(excluded.platform,hosts.platform),
                architecture=COALESCE(excluded.architecture,hosts.architecture), last_seen=excluded.last_seen
                """,
                (workspace_id, address, hostname, platform, architecture, now, now),
            )
            return db.execute(
                "SELECT * FROM hosts WHERE workspace_id=? AND address=?",
                (workspace_id, address),
            ).fetchone()

    def list_hosts(self, workspace):
        """Return hosts with service and finding counts."""
        wid = self.ensure_workspace(workspace)

        with self._connect() as db:
            return db.execute(
                """
                SELECT h.*, (SELECT COUNT(*) FROM services s WHERE s.host_id=h.id) service_count,
                (SELECT COUNT(*) FROM findings f WHERE f.host_id=h.id) finding_count FROM hosts h
                WHERE h.workspace_id=? ORDER BY h.address
                """,
                (wid,),
            ).fetchall()

    def get_host(self, workspace, identifier):
        """Find a host by address or database ID."""
        wid = self.ensure_workspace(workspace)

        with self._connect() as db:
            return db.execute(
                "SELECT * FROM hosts WHERE workspace_id=? AND (address=? OR CAST(id AS TEXT)=?)",
                (
                    wid,
                    str(identifier),
                    str(identifier),
                ),
            ).fetchone()

    def add_service(self, workspace, host, protocol, port, name=None, product=None, version=None):
        """Insert or update a service record."""
        host_row = self.get_host(workspace, host)
        if host_row is None:
            raise ValueError(f"Host {host!r} is not present in workspace {workspace!r}.")

        protocol = str(protocol).lower()
        if protocol not in {"tcp", "udp"}:
            raise ValueError("Protocol must be tcp or udp.")

        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

        now = self._now()
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO services(host_id,protocol,port,name,product,version,observed_at) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(host_id,protocol,port) DO UPDATE SET name=COALESCE(excluded.name,services.name),
                product=COALESCE(excluded.product,services.product), version=COALESCE(excluded.version,services.version),
                observed_at=excluded.observed_at
                """,
                (
                    host_row["id"],
                    protocol,
                    port,
                    name,
                    product,
                    version,
                    now,
                ),
            )
            return db.execute(
                "SELECT * FROM services WHERE host_id=? AND protocol=? AND port=?",
                (
                    host_row["id"],
                    protocol,
                    port,
                ),
            ).fetchone()

    def list_services(self, workspace, host=None):
        """Return services, optionally filtered by host."""
        wid = self.ensure_workspace(workspace)

        query = "SELECT s.*,h.address FROM services s JOIN hosts h ON h.id=s.host_id WHERE h.workspace_id=?"
        params = [wid]
        if host is not None:
            query += " AND (h.address=? OR CAST(h.id AS TEXT)=?)"
            params.extend((str(host), str(host)))

        with self._connect() as db:
            return db.execute(
                query + " ORDER BY h.address,s.protocol,s.port",
                params,
            ).fetchall()

    def add_finding(self, workspace, host, title, severity="info"):
        """Insert an assessment finding for a host."""
        host_row = self.get_host(workspace, host)
        if host_row is None:
            raise ValueError(f"Host {host!r} is not present in workspace {workspace!r}.")

        severity = str(severity).lower()
        if severity not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("Severity must be info, low, medium, high, or critical.")

        now = self._now()
        with self._connect() as db:
            cursor = db.execute(
                "INSERT INTO findings(host_id,title,severity,created_at,updated_at) VALUES(?,?,?,?,?)",
                (
                    host_row["id"],
                    str(title).strip(),
                    severity,
                    now,
                    now,
                ),
            )
            return db.execute(
                "SELECT * FROM findings WHERE id=?",
                (cursor.lastrowid,),
            ).fetchone()

    def list_findings(self, workspace, host=None):
        """Return findings, optionally filtered by host."""
        wid = self.ensure_workspace(workspace)

        query = "SELECT f.*,h.address FROM findings f JOIN hosts h ON h.id=f.host_id WHERE h.workspace_id=?"
        params = [wid]
        if host is not None:
            query += " AND (h.address=? OR CAST(h.id AS TEXT)=?)"
            params.extend((str(host), str(host)))

        with self._connect() as db:
            return db.execute(
                query + " ORDER BY f.created_at DESC,f.id DESC",
                params,
            ).fetchall()
