from teralibs.terasploit.framework.console.terasploit import Terasploit


class BaseConsole(Terasploit):
    """Provide shared framework state to the console and its components."""

    def flush_job_output(self) -> None:
        """Provide a hook for draining background-job output."""
        raise NotImplementedError
