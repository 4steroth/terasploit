from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_PYTHON, PLATFORM_PYTHON, STAGER, PayloadHandler
from teralibs.tsf.core.payload.python.reverse_tcp import PythonReverseTCP


class TerasploitModule(PythonReverseTCP):
    """Python Reverse TCP Stager."""

    NAME: str = "Python Reverse TCP Stager"
    DESCRIPTION: str = "Reverse Python connect back stager. Built to use shell stage."
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = []
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.ReverseTCP
    STAGE_PATH: str = "python.shell"
    CACHED_SIZE: int = 1116
    ARCH: Sequence = [ARCH_PYTHON]
    PLATFORM: Sequence = [PLATFORM_PYTHON]
