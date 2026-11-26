# Shell
from extension.shell.base import BaseShell
from extension.shell.generic import GenericShell
from extension.shell.unix import UnixShell
from extension.shell.windows import WindowsShell


MAP = {
    "unix": UnixShell,
    "linux": UnixShell,
    "bsd": UnixShell,
    "macos": UnixShell,
    "darwin": UnixShell,
    "windows": WindowsShell,
    "win": WindowsShell,
    "win32": WindowsShell,
    "win64": WindowsShell,
}


def select_shell(session, platform=None, session_registry_fn=None, loot_manager=None):
    """Return the appropriate shell instance for *platform*"""
    platform_key = (platform or getattr(session, "platform", None) or "").lower().strip()

    cls = MAP.get(platform_key, GenericShell)
    return cls(session=session, session_registry_fn=session_registry_fn, loot_manager=loot_manager)


__all__ = ["BaseShell", "GenericShell", "UnixShell", "WindowsShell", "select_shell"]
