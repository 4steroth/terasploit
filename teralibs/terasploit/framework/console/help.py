help_sections = [
    (
        "Core",
        [
            ("help / ?", "Show this help menu"),
            ("banner", "Display the terasploit framework banner"),
            ("exit / quit", "Exit the console"),
            ("clear", "Clear the terminal screen"),
            ("exec <command>", "Execute a system shell command"),
        ],
    ),
    (
        "Module",
        [
            ("use <module>", "Load a module by name or path"),
            ("back", "Unload the current module"),
            ("info [module]", "Show module metadata"),
            ("search <query>", "Search available modules"),
            ("reload", "Rescan module index and reset encoder cache"),
            ("show all", "List all available modules"),
            ("show options", "Basic options and targets for the active module"),
            ("show advanced", "Advanced options for the active module and payload"),
            ("show evasion", "Evasion options for the active module and payload"),
            ("show targets", "Targets for the active module"),
            ("show payloads", "List payload modules"),
            ("show exploits", "List exploit modules"),
            ("show auxiliary", "List auxiliary modules"),
            ("show encoders", "List encoder modules"),
        ],
    ),
    (
        "Options",
        [
            ("set <name> <value>", "Set a module/framework option"),
            ("set PAYLOAD <path>", "Load and validate a payload"),
            ("set TARGET <id>", "Select a target by numeric ID"),
            ("unset <name>", "Reset a module option to empty"),
        ],
    ),
    (
        "Execution",
        [
            ("run / exploit", "Execute module - blocks until done, Ctrl-C to kill"),
            ("check", "Test target vulnerability without exploiting"),
            ("jobs", "List all jobs and their status"),
            ("jobs clear", "Remove completed / failed / killed jobs"),
        ],
    ),
    (
        "Sessions",
        [
            ("sessions", "List all open sessions"),
            ("sessions -C <id> <cmd>", "Run a single command on a session inline"),
            ("interact <id>", "Attach to an open session"),
            ("interact <id> <plat>", "Attach with platform hint (unix/windows)"),
            ("kill <session_id>", "Close a TCP session gracefully"),
            ("kill <job_id>", "Stop a running job and shut its listener down"),
            ("kill all", "Close every open session"),
        ],
    ),
    (
        "Nop",
        [
            ("generate [size] [-b <bc>]", "Generate a NOP sled from the active nop module"),
        ],
    ),
]
