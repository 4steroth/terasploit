from terasploit.database.manager import IntelligenceDatabase


class IntelManager:
    """Provide a stable interface for recording and querying assessment data."""

    def __init__(self, datastore, database=None):
        self.datastore = datastore
        self.database = database or IntelligenceDatabase()

    @property
    def workspace(self):
        """Return the active workspace, falling back to ``default``."""
        value = self.datastore.get_value("WORKSPACE")
        return str(value or "default").strip() or "default"

    def use_workspace(self, name):
        """Create a workspace if needed and make it active."""
        name = str(name).strip()

        self.database.ensure_workspace(name)
        self.datastore.set_value("WORKSPACE", name, scope="framework")

        return name

    def list_workspaces(self):
        """Return all known workspaces."""
        return self.database.list_workspaces()

    def add_host(self, address, hostname=None, platform=None, architecture=None, *, workspace=None):
        """Register or update a host in the selected workspace."""
        return self.database.add_host(
            workspace or self.workspace,
            address,
            hostname,
            platform,
            architecture,
        )

    def get_host(self, identifier, *, workspace=None):
        """Find a host by address or database ID."""
        return self.database.get_host(
            workspace or self.workspace,
            identifier,
        )

    def list_hosts(self, *, workspace=None):
        """Return hosts and their service/finding counts."""
        return self.database.list_hosts(workspace or self.workspace)

    def add_service(self, host, protocol, port, name=None, product=None, version=None, *, workspace=None):
        """Record or update an observed host service."""
        return self.database.add_service(
            workspace or self.workspace,
            host,
            protocol,
            port,
            name,
            product,
            version,
        )

    def list_services(self, host=None, *, workspace=None):
        """Return observed services, optionally filtered by host."""
        return self.database.list_services(workspace or self.workspace, host)

    def add_finding(self, host, title, severity="info", *, workspace=None):
        """Record an assessment finding for a known host."""
        return self.database.add_finding(
            workspace or self.workspace,
            host,
            title,
            severity,
        )

    def list_findings(self, host=None, *, workspace=None):
        """Return assessment findings, optionally filtered by host."""
        return self.database.list_findings(workspace or self.workspace, host)
