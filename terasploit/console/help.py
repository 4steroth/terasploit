SECTIONS = [
    (
        "Core",
        [
            (
                "help / ?",
                "Show this help menu",
            ),
            (
                "banner",
                "Display the terasploit framework banner",
            ),
            (
                "exit / quit",
                "Exit the console",
            ),
            (
                "clear",
                "Clear the terminal screen",
            ),
            (
                "exec <command>",
                "Execute a system shell command",
            ),
            (
                "record start [file]",
                "Start recording console activity",
            ),
            (
                "record stop",
                "Stop the active transcript recording",
            ),
            (
                "record status",
                "Display the current recording status",
            ),
        ],
    ),
    (
        "Module",
        [
            (
                "use <module>",
                "Load a module by name or path",
            ),
            (
                "back",
                "Unload the current module",
            ),
            (
                "info [module]",
                "Show module metadata",
            ),
            (
                "search <query>",
                "Search available modules",
            ),
            (
                "reload",
                "Rescan module index and reset encoder cache",
            ),
            (
                "show all",
                "List all available modules",
            ),
            (
                "show options",
                "Basic options and targets for the active module",
            ),
            (
                "show advanced",
                "Advanced options for the active module and payload",
            ),
            (
                "show evasion",
                "Evasion options for the active module and payload",
            ),
            (
                "show targets",
                "Targets for the active module",
            ),
            (
                "show payloads",
                "List payload modules",
            ),
            (
                "show exploits",
                "List exploit modules",
            ),
            (
                "show auxiliary",
                "List auxiliary modules",
            ),
            (
                "show encoders",
                "List encoder modules",
            ),
        ],
    ),
    (
        "Options",
        [
            (
                "set <name> <value>",
                "Set a module/framework option",
            ),
            (
                "set PAYLOAD <path>",
                "Load and validate a payload",
            ),
            (
                "set TARGET <id>",
                "Select a target by numeric ID",
            ),
            (
                "unset <name>",
                "Reset a module option to empty",
            ),
        ],
    ),
    (
        "Execution",
        [
            (
                "run / exploit",
                "Execute module - blocks until done, Ctrl-C to kill",
            ),
            (
                "check",
                "Test target vulnerability without exploiting",
            ),
            (
                "jobs",
                "List all jobs and their status",
            ),
            (
                "jobs clear",
                "Remove completed / failed / killed jobs",
            ),
        ],
    ),
    (
        "Sessions",
        [
            (
                "sessions",
                "List all open sessions",
            ),
            (
                "sessions -H",
                "Browse persisted session history",
            ),
            (
                "sessions -H <id>",
                "Inspect a historical session record",
            ),
            (
                "sessions -H -w <workspace> [-p <platform>]",
                "Filter historical sessions",
            ),
            (
                "sessions -C <id> <cmd>",
                "Run a single command on a session inline",
            ),
            (
                "interact <id>",
                "Attach to an open session",
            ),
            (
                "interact <id> <plat>",
                "Attach with platform hint (unix/windows)",
            ),
            (
                "kill <session_id>",
                "Close a TCP session gracefully",
            ),
            (
                "kill <job_id>",
                "Stop a running job and shut its listener down",
            ),
            (
                "kill all",
                "Close every open session",
            ),
        ],
    ),
    (
        "Loot",
        [
            (
                "loot",
                "List artifacts in the active workspace",
            ),
            (
                "loot -H <host>",
                "Filter artifacts by host address or ID",
            ),
            (
                "loot -S <session>",
                "Filter artifacts by session ID",
            ),
            (
                "loot -i <id>",
                "Inspect artifact metadata and SHA-256",
            ),
            (
                "loot -e <id> <path>",
                "Export an artifact to a local path",
            ),
            (
                "loot -d <id>",
                "Delete an artifact and its stored file",
            ),
            (
                "loot -w <workspace>",
                "Browse artifacts in another workspace",
            ),
        ],
    ),
    (
        "Intelligence",
        [
            (
                "workspace list",
                "List available target-intelligence workspaces",
            ),
            (
                "workspace create <name>",
                "Create and select a workspace",
            ),
            (
                "workspace use <name>",
                "Switch the active workspace",
            ),
            (
                "hosts",
                "List hosts in the active workspace",
            ),
            (
                "hosts add <address> [hostname] [platform] [arch]",
                "Register or update a host",
            ),
            (
                "hosts info <host>",
                "Display recorded host information",
            ),
            (
                "services",
                "List observed services",
            ),
            (
                "services add <host> <tcp|udp> <port> [name] [product] [version]",
                "Record an observed service",
            ),
            (
                "vulns",
                "List assessment findings",
            ),
            (
                "vulns add <host> <severity> <title>",
                "Record an assessment finding",
            ),
        ],
    ),
]
