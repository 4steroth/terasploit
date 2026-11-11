from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_PHP, PLATFORM_PHP, STAGER, PayloadHandler
from teralibs.tsf.core.payload.php.reverse_tcp import PHPReverseTCP


class TerasploitModule(PHPReverseTCP):
    """PHP Reverse TCP Stager."""

    NAME: str = "PHP Reverse TCP Stager"
    DESCRIPTION: str = "Reverse PHP connect back stager. Built to use shell stage."
    AUTHOR: Sequence = ["egypt", "4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = ["https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/php/reverse_tcp.rb"]
    PAYLOAD_TYPE: str = STAGER
    HANDLER: object = PayloadHandler.ReverseTCP
    STAGE_PATH: str = "php.shell"
    CACHED_SIZE: int = 1116
    ARCH: Sequence = [ARCH_PHP]
    PLATFORM: Sequence = [PLATFORM_PHP]
