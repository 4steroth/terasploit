from terasploit.ui import tables as tbl
from terasploit.ui.printf import (
    error,
    info,
    print_line,
    success,
    warning,
)


class IntelligenceCommands:
    """Manage workspace-scoped target intelligence."""

    def __init__(self, console):
        self.console = console
        self.intelligence = console.intelligence

    @property
    def workspace(self):
        """Return the active workspace name."""
        return str(self.console.datastore.get_value("WORKSPACE") or "default").strip() or "default"

    def cmd_workspace(self, args):
        """List, create, or select an intelligence workspace."""
        if not args or args[0].lower() == "list":
            rows = self.intelligence.list_workspaces()
            active = self.workspace

            print_line("\nWorkspaces\n==========\n")

            names = {row["name"] for row in rows} | {active}
            for name in sorted(names):
                print_line(f" {'*' if name == active else ' '} {name}")

            print_line()
            return

        action = args[0].lower()
        if action == "current":
            info(f"Active workspace: {self.workspace}")
            return
        if action in {"use", "create"} and len(args) == 2:
            name = args[1]
            try:
                self.intelligence.use_workspace(name)
            except (ValueError, OSError) as exc:
                error(str(exc))
                return

            success(f"Workspace set to '{name}'.")
            return

        warning("Usage: workspace [list | current | use <name> | create <name>]")

    def cmd_hosts(self, args):
        """List, inspect, or register hosts in the active workspace."""
        if not args or args[0].lower() in {"list", "-l"}:
            print_line("\nHosts\n=====\n")

            rows = self.intelligence.list_hosts()
            if not rows:
                info("No hosts recorded in this workspace.")
                return

            tbl.render_table(
                ("ID", "Address", "Hostname", "Platform", "Arch", "Services", "Findings"),
                [
                    (
                        row["id"],
                        row["address"],
                        row["hostname"] or ".",
                        row["platform"] or ".",
                        row["architecture"] or ".",
                        row["service_count"],
                        row["finding_count"],
                    )
                    for row in rows
                ],
                min_widths=[2, 7, 8, 8, 12, 13, 13],
                padding=1,
            )
            print_line()
            return

        if args[0].lower() == "add" and 2 <= len(args) <= 5:
            values = args[2:] + [None] * (3 - len(args[2:]))
            try:
                row = self.intelligence.add_host(args[1], *values)
            except (ValueError, OSError) as exc:
                error(str(exc))
                return

            success(f"Host {row['address']} recorded (ID {row['id']}).")
            return

        if args[0].lower() == "info" and len(args) == 2:
            row = self.intelligence.get_host(args[1])
            if row is None:
                error(f"Host {args[1]!r} was not found.")
                return

            for key in ("id", "address", "hostname", "platform", "architecture", "first_seen", "last_seen"):
                print_line(f"{key.replace('_', ' ').title():<16} {row[key] or '-'}")

            return

        warning("Usage: hosts [list | add <address> [hostname] [platform] [architecture] | info <host>]")

    def cmd_services(self, args):
        """List or register observed services."""
        if args and args[0].lower() == "add":
            if len(args) < 4 or len(args) > 7:
                warning("Usage: services add <host> <tcp|udp> <port> [name] [product] [version]")
                return

            values = args[4:] + [None] * (3 - len(args[4:]))
            try:
                row = self.intelligence.add_service(args[1], args[2], args[3], *values)
            except (ValueError, OSError) as exc:
                error(str(exc))
                return

            success(f"Service {row['protocol']}/{row['port']} recorded for {args[1]}.")
            return

        host = args[1] if len(args) == 2 and args[0].lower() in {"-h", "--host"} else None
        rows = self.intelligence.list_services(host)

        print_line("\nServices\n========\n")
        if not rows:
            info("No services recorded.")
            return

        tbl.render_table(
            ("Host", "Proto", "Port", "Service", "Product / Version"),
            [
                (
                    row["address"],
                    row["protocol"],
                    row["port"],
                    row["name"] or "-",
                    " ".join(part for part in (row["product"], row["version"]) if part) or "-",
                )
                for row in rows
            ],
            min_widths=[12, 4, 4, 7, 12],
            padding=1,
        )
        print_line()

    def cmd_vulns(self, args):
        """List or record assessment findings."""
        if args and args[0].lower() == "add":
            if len(args) < 4:
                warning("Usage: vulns add <host> <severity> <title>")
                return
            try:
                row = self.intelligence.add_finding(args[1], " ".join(args[3:]), args[2])
            except (ValueError, OSError) as exc:
                error(str(exc))
                return

            success(f"Finding #{row['id']} recorded for {args[1]}.")
            return

        host = args[1] if len(args) == 2 and args[0].lower() in {"-h", "--host"} else None
        rows = self.intelligence.list_findings(host)

        print_line("\nFindings\n========\n")
        if not rows:
            info("No findings recorded.")
            return

        items = [(row["id"], row["address"], row["severity"], row["title"]) for row in rows]
        items.sort()

        tbl.render_table(
            ("ID", "Host", "Severity", "Title"),
            items,
            min_widths=[3, 12, 8, 12],
            padding=1,
        )
        print_line()
