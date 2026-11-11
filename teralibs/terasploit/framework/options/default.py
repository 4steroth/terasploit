import dataclasses
from dataclasses import field
from typing import Any

from teralibs.terasploit.framework.options.validators import OptionType


@dataclasses.dataclass
class Option:
    """Descriptor for a single user-configurable setting."""

    name: str
    default: Any = None
    required: bool = False
    desc: str = ""
    opt_type: str | None = None
    choices: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.choices = self.choices or []

    @property
    def key(self):
        """Return name in uppercase to serve as key."""
        return self.name.upper()

    def __repr__(self):
        return f"Option({self.name!r}, default={self.default!r}, required={self.required}, opt_type={self.opt_type!r})"


# Default options base on category.

NETWORK_OPTIONS = [
    Option(
        "LHOST",
        None,
        True,
        "Attacker IP or hostname to connect back to",
        OptionType.ADDRESS,
    ),
    Option(
        "LPORT",
        4444,
        True,
        "Local listener port",
        OptionType.PORT,
    ),
    Option(
        "RHOST",
        None,
        True,
        "Remote host address",
        OptionType.ADDRESS,
    ),
    Option(
        "RPORT",
        None,
        True,
        "Remote port",
        OptionType.PORT,
    ),
    Option(
        "PROXIES",
        None,
        False,
        "A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks5, socks5h, sapni, http, socks4",
        OptionType.STRING,
    ),
]

PAYLOAD_OPTIONS = [
    Option(
        "BADCHARS",
        None,
        False,
        "Bytes the payload must not contain (e.g. '\\x00')",
        OptionType.STRING,
    ),
    Option(
        "BADCHARS_STRICT",
        "false",
        False,
        "Block delivery if bad bytes cannot be encoded",
        OptionType.BOOL,
    ),
    Option(
        "NopSledSize",
        "0",
        False,
        "Prepend a NOP sled of this many bytes to the payload",
        OptionType.INTEGER,
    ),
    Option(
        "NopSledModule",
        None,
        False,
        "Explicit nop module path for sled generation (auto-select when empty)",
        OptionType.STRING,
    ),
    Option(
        "EXITFUNC",
        "process",
        True,
        "Exit technique to use",
        OptionType.ENUM,
        choices=["none", "seh", "process", "thread", "sleep"],
    ),
    Option(
        "SHELL",
        "/bin/sh",
        True,
        "The shell to use for execution",
        OptionType.ENUM,
        [
            "/bin/sh",
            "/bin/bash",
            "/bin/zsh",
            "/bin/dash",
            "cmd.exe",
            "powershell.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ],
    ),
]

# Pre-defined option sets
FRAMEWORK_CORE_OPTIONS = [
    Option(
        "VERBOSE",
        "false",
        False,
        "Enable debug/verbose output for all log channels (true/false)",
        OptionType.BOOL,
    ),
    Option(
        "PROMPT",
        "tsf",
        False,
        "Text label displayed at the start of the console prompt",
        OptionType.STRING,
    ),
    Option(
        "PROMPT_CHAR",
        ">",
        False,
        "Character appended after the prompt label",
        OptionType.STRING,
    ),
    Option(
        "MAX_THREADS",
        "10",
        False,
        "Maximum number of concurrent exploit execution threads",
        OptionType.INTEGER,
    ),
    Option(
        "HISTORY_LENGTH",
        "1000",
        False,
        "Number of console commands retained in the readline history file",
        OptionType.INTEGER,
    ),
    Option(
        "TIMESTAMP_OUTPUT",
        "false",
        False,
        "Prepend an HH:MM:SS timestamp to every console log line",
        OptionType.BOOL,
    ),
    Option(
        "SESSION_TIMEOUT",
        "1800",
        False,
        "Idle seconds before a session is flagged as stale",
        OptionType.INTEGER,
    ),
    Option(
        "WORKSPACE",
        None,
        False,
        "Active workspace name - session files are grouped under session/<workspace>/",
        OptionType.STRING,
    ),
]

DRIVER_ADVANCED_OPTIONS = [
    Option(
        "DisablePayloadHandler",
        "false",
        False,
        "Disable the handler code for the selected payload",
        OptionType.BOOL,
    ),
    Option(
        "EnableContextEncoding",
        "false",
        False,
        "Use transient context when encoding payloads",
        OptionType.BOOL,
    ),
    Option(
        "ExitOnSession",
        "true",
        False,
        "Return from the exploit after a session has been created",
        OptionType.BOOL,
    ),
    Option(
        "ListenerTimeout",
        "0",
        False,
        "The maximum number of seconds to wait for new sessions",
        OptionType.INTEGER,
    ),
    Option(
        "WfsDelay",
        "2",
        False,
        "Additional delay in seconds to wait for a session",
        OptionType.FLOAT,
    ),
]

PAYLOAD_ADVANCED_OPTIONS = [
    # Session comm-test - applies to any payload that opens a shell session.
    Option(
        "SessionCommunicationTimeout",
        "10",
        False,
        ("Seconds to wait for the shell comm-test echo response after a session is opened. Set to 0 to skip the comm test entirely."),
        OptionType.FLOAT,
    ),
    Option(
        "SessionRetryTotal",
        "1",
        False,
        ("Total number of comm-test retry attempts before the session is declared invalid."),
        OptionType.INTEGER,
    ),
    Option(
        "SessionRetryWait",
        "5",
        False,
        "Seconds to wait between comm-test retry attempts.",
        OptionType.FLOAT,
    ),
]

REVERSE_TCP_ADVANCED_OPTIONS = [
    Option(
        "ReverseAllowProxy",
        "false",
        False,
        "Allow reverse TCP even when a proxy is configured in the environment",
        OptionType.BOOL,
    ),
    Option(
        "ReverseListenerBindAddress",
        None,
        False,
        "Specific IP address to bind to on the local system (overrides LHOST)",
        OptionType.ADDRESS,
    ),
    Option(
        "ReverseListenerBindPort",
        None,
        False,
        "Port to bind to on the local system if different from LPORT",
        OptionType.PORT,
    ),
    Option(
        "ReverseListenerComm",
        None,
        False,
        ("Communication channel for the listener - an IP acts as a bind-address override; an interface name (e.g. eth0) requires OS-level routing."),
        OptionType.STRING,
    ),
    Option(
        "ReverseListenerThreaded",
        "false",
        False,
        "Accept every inbound connection in a separate thread (experimental)",
        OptionType.BOOL,
    ),
]

STAGER_ADVANCED_OPTIONS = [
    Option(
        "StagerRetryCount",
        "10",
        False,
        "Number of times the stager retries if the first connect fails",
        OptionType.INTEGER,
    ),
    Option(
        "StagerRetryWait",
        "5",
        False,
        "Seconds to wait between stager reconnect attempts",
        OptionType.INTEGER,
    ),
]

PAYLOAD_EVASION_OPTIONS = [
    # Stage encoding - encode the stage in transit to evade IDS signatures.
    Option(
        "EnableStageEncoding",
        "false",
        False,
        (
            "Encode the stage payload before sending. When true the stage is "
            "run through the encoder selected by StageEncoder (or auto-selected "
            "when StageEncoder is blank)."
        ),
        OptionType.BOOL,
    ),
    Option(
        "StageEncoder",
        None,
        False,
        ("Encoder to use when EnableStageEncoding is true. Leave blank to auto-select the highest-ranked compatible encoder."),
        OptionType.STRING,
    ),
    Option(
        "StageEncoderSavedRegisters",
        None,
        False,
        ("Comma-separated list of registers the stage encoder must preserve (e.g. 'rbx,r12'). Passed to the encoder as a hint."),
        OptionType.STRING,
    ),
]

POST_MODULE_OPTIONS = [
    Option(
        "SESSION",
        None,
        True,
        "Session ID to run this module against",
        OptionType.STRING,
    ),
]
