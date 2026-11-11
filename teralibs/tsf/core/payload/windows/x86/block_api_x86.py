import os
import random
import re
import struct

from teralibs.tsf.pex.payloads.shuffle import Shuffle
from teralibs.tsf.pex.text import Text


class BlockApiX86:
    """Basic block_api stubs for Windows payloads."""

    def __init__(self):
        self.blockapi_iv_cache: int | None = None

        # Root data directory resolved relative to this file's location.
        root = os.path.abspath(__file__)
        for _ in range(7):
            root = os.path.dirname(root)

        self.data_dir = os.path.join(root, "data", "shellcode")

    def block_api_iv(self, _) -> int:
        """Returns or dynamically generates a cached 32-bit unsigned integer random value."""
        if self.blockapi_iv_cache is None:
            self.blockapi_iv_cache = random.randint(0, 0xFFFFFFFF)

        return self.blockapi_iv_cache

    def asm_block_api(self, opts=None):
        """Builds the x86 block_api assembly stub from its GraphML template."""
        if opts is None:
            opts = {}

        asm = Shuffle.from_graphml_file(os.path.join(self.data_dir, "block_api.x86.graphml"), arch="x86", name="api_call")

        iv = opts.get("block_api_iv", self.block_api_iv(opts))
        iv_bytes = ", ".join(f"0x{b:02x}" for b in struct.pack("<I", iv))

        pattern = (
            r"db\s+0xbf,\s*"
            r"0x00,\s*0x00,\s*0x00,\s*0x00"
        )

        replacement = f"db 0xbf, {iv_bytes}"
        patched, count = re.subn(pattern, replacement, asm, count=1, flags=re.IGNORECASE)

        if count != 1:
            raise RuntimeError(f"Failed to locate block_api IV placeholder (wanted IV 0x{iv:08x})")

        return patched

    def block_api_hash(self, mod, func, opts=None):
        """Computes the target API hashing resolution routine signature."""
        iv = self.block_api_iv(opts) if opts is None or not opts.get("block_iv_cache") else opts.get("block_iv_cache")
        if opts is not None:
            opts["block_iv_cache"] = iv

        return Text.block_api_hash(mod, func, iv=iv)
