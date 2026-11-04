import dataclasses
import random
import threading
from collections.abc import Callable
from enum import Enum

from teralibs.tsf.utils.exception import PythonExploitationLibraryError


_registry_local = threading.local()


def _get_registry() -> dict:
    if not hasattr(_registry_local, "blocks"):
        _registry_local.blocks = {}
    return _registry_local.blocks


class EncodingError(Exception):
    """Raised when the mutation engine cannot satisfy conditions without hit bad bytes."""


@dataclasses.dataclass(init=True)
class LogicalRegister:
    """Tracks architecture registers and registers targeted for allocation or constraint."""

    name: str
    fixed_reg: str | None = None


class SymbolicBlock(Enum):
    """
    Represents special symbolic references to key layout
    positions that can be used in dynamic permutation expressions.
    """

    END = "__end_marker__"
    # START = "__start_marker__" # (Easy to expand later if needed)


class StateSnapshot:
    """Internal runtime state capturing current assignments during permutation evaluations."""

    def __init__(self, reg_map: dict[str, int], offsets: dict[str, int]):
        self.reg_map = reg_map  # Mappings from LogicalRegister identity string -> integer register ID
        self.offsets = offsets  # Mappings from LogicalBlock identity string -> relative byte offset

    def regnum_of(self, reg) -> int:
        """Resolve the assigned register number for a given LogicalRegister or named object."""
        if reg.name not in self.reg_map:
            raise EncodingError(f"Register reference '{reg.name}' was not allocated.")
        return self.reg_map[reg.name]

    def offset_of(self, block) -> int:
        """
        Resolve the assigned byte offset for a given LogicalBlock or SymbolicBlock.
        """
        if block == SymbolicBlock.END:
            return self.offsets.get("__end_marker__", 0)

        if block.name not in self.offsets:
            raise EncodingError(f"Offset reference for block '{block.name}' unresolved.")

        return self.offsets[block.name]


class LogicalBlock:
    """
    Represents an atomic assembly instruction or sequence payload block that
    supports multiple valid structural or opcode permutations.
    """

    # Define a clean type alias for clarity: accepts raw bytes OR a generator function
    PermutationType = bytes | Callable[[StateSnapshot], bytes]

    def __new__(cls, name: str, *static_perms):
        registry = _get_registry()
        if name in registry:
            existing = registry[name]
            # Append any new static perms provided in this call.
            if static_perms:
                existing.perms.extend(static_perms)
            return existing
        instance = super().__new__(cls)
        registry[name] = instance
        return instance

    def __init__(self, name: str, *static_perms: PermutationType):
        if hasattr(self, "_initialised"):
            return
        self._initialised = True
        self.name = name
        self.perms: list[LogicalBlock.PermutationType] = list(static_perms)
        self.dependencies: list[LogicalBlock] = []

    @staticmethod
    def reset_registry() -> None:
        """Clear the thread-local block registry."""
        _get_registry().clear()

    def add_perm(self, *perms: PermutationType):
        """
        Add additional permutation variants to this
        block's repertoire, ensuring type consistency.
        """
        self.perms.extend(perms)

    def depends_on(self, *blocks):
        """Declare that this block depends on the presence of other blocks."""
        for b in blocks:
            if b not in self.dependencies:
                self.dependencies.append(b)

    def collect_all_blocks(self, visited: set[str], order: list):
        """Perform topological sort across nested dependencies to determine build order."""
        if self.name in visited:
            return
        for dep in self.dependencies:
            dep.collect_all_blocks(visited, order)

        visited.add(self.name)
        order.append(self)

    def generate(
        self,
        register_blacklist: list[int],
        active_registers=None,
        bad_bytes: frozenset = frozenset(),
    ) -> bytes:
        """
        Main solver loop. Finds an ordered graph sequence and tests valid permutation
        variants until a candidate fully evades bad_bytes.
        """
        # 1. Gather full layout sequence order via dependencies
        generation_order: list = []
        self.collect_all_blocks(set(), generation_order)

        # 2. Build the comprehensive register configuration
        all_registers = self._build_register_set(generation_order, active_registers)

        # 3. Brute-force solver loop
        max_attempts = 250
        for _ in range(max_attempts):
            reg_map = self._attempt_register_mapping(all_registers, register_blacklist)
            if not reg_map:
                continue

            # Select random permutation configurations
            chosen_perms = self._select_permutations(generation_order)

            # Two-pass sizing to accommodate dynamic layout dependencies
            final_offsets = self._compute_layout_offsets(generation_order, chosen_perms, reg_map)

            # Attempt final compilation and validation
            candidate_bytes = self._compile_and_validate(chosen_perms, reg_map, final_offsets, bad_bytes)
            if candidate_bytes is not None:
                return candidate_bytes

        raise EncodingError("Polymorphic engine layout failed to satisfy target constraints without hitting bad chars.")

    def _build_register_set(self, generation_order: list, active_registers) -> dict[str, LogicalRegister]:
        """
        Populates and returns the complete registry dictionary, synthesizing missing
        implied components from well-known naming blocks in the dependency sequence.
        """
        all_registers: dict[str, LogicalRegister] = {}

        if active_registers:
            for reg in active_registers:
                all_registers[reg.name] = reg

        # Fallback: infer registers from block name patterns when not supplied explicitly
        for block in generation_order:
            if ("clear_register" in block.name or "init_counter" in block.name) and "count" not in all_registers:
                all_registers["count"] = LogicalRegister("count", "ecx")
            if "init_key" in block.name and "key" not in all_registers:
                all_registers["key"] = LogicalRegister("key")

        if "addr" not in all_registers:
            all_registers["addr"] = LogicalRegister("addr")

        return all_registers

    def _attempt_register_mapping(self, all_registers: dict[str, LogicalRegister], register_blacklist: list[int]) -> dict[str, int] | None:
        """
        Attempts to generate a random register mapping variation that respects x86 architectural
        constraints and excludes blacklisted target registers. Returns None if pool exhausts.
        """
        reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
        reg_map: dict[str, int] = {}
        available_pool = [i for i in range(8) if i not in register_blacklist]

        # Lock explicit/fixed register demands
        for reg_obj in all_registers.values():
            if reg_obj.fixed_reg and reg_obj.fixed_reg in reg_names:
                idx = reg_names.index(reg_obj.fixed_reg)
                reg_map[reg_obj.name] = idx
                if idx in available_pool:
                    available_pool.remove(idx)

        # Assign dynamic variables randomly to unallocated spaces
        shuffled_pool = list(available_pool)
        random.shuffle(shuffled_pool)

        for reg_obj in all_registers.values():
            if reg_obj.name not in reg_map:
                if not shuffled_pool:
                    continue
                reg_map[reg_obj.name] = shuffled_pool.pop()

        if len(reg_map) < len(all_registers):
            return None  # Incomplete mapping constellation

        return reg_map

    def _select_permutations(self, generation_order: list) -> list[bytes | Callable[[StateSnapshot], bytes]]:
        """Selects a single random permutation variant from each logical block's choice pool."""
        chosen_perms: list[bytes | Callable[[StateSnapshot], bytes]] = []
        for b in generation_order:
            perms_copy = list(b.perms)
            random.shuffle(perms_copy)
            chosen_perms.append(perms_copy[0])
        return chosen_perms

    def _compute_layout_offsets(
        self,
        generation_order: list,
        chosen_perms: list[bytes | Callable[[StateSnapshot], bytes]],
        reg_map: dict[str, int],
    ) -> dict[str, int]:
        """
        Executes a two-pass offset evaluation. The first pass calculates a provisional
        end-marker, and the second pass refines offset markers targeting precise output lengths.
        """
        current_offset = 0
        provisional_offsets: dict[str, int] = {}
        for b, perm in zip(generation_order, chosen_perms, strict=False):
            provisional_offsets[b.name] = current_offset
            if callable(perm):
                temp_snapshot = StateSnapshot(reg_map, {**provisional_offsets, "__end_marker__": current_offset + 4})
                try:
                    current_offset += len(perm(temp_snapshot))

                except PythonExploitationLibraryError:
                    current_offset += 4
            else:
                current_offset += len(perm)

        total_length_guess = current_offset
        final_offsets: dict[str, int] = {}
        current_offset = 0

        for b, perm in zip(generation_order, chosen_perms, strict=False):
            final_offsets[b.name] = current_offset
            if callable(perm):
                accurate_snapshot = StateSnapshot(
                    reg_map,
                    {**final_offsets, "__end_marker__": total_length_guess},
                )
                try:
                    current_offset += len(perm(accurate_snapshot))

                except PythonExploitationLibraryError:
                    current_offset += 4
            else:
                current_offset += len(perm)

        final_offsets["__end_marker__"] = current_offset
        return final_offsets

    def _compile_and_validate(
        self,
        chosen_perms: list[bytes | Callable[[StateSnapshot], bytes]],
        reg_map: dict[str, int],
        offsets: dict[str, int],
        bad_bytes: frozenset,
    ) -> bytes | None:
        """
        Assembles individual permutation components under the finalized offset map state,
        validating that no emitted instructions contain forbidden bad bytes.
        """
        snapshot = StateSnapshot(reg_map, offsets)
        compiled_buffer = bytearray()

        for perm in chosen_perms:
            try:
                block_bytes = perm(snapshot) if callable(perm) else perm

                if any(byte in bad_bytes for byte in block_bytes):
                    return None
                compiled_buffer.extend(block_bytes)

            except PythonExploitationLibraryError:
                return None

        return bytes(compiled_buffer)
