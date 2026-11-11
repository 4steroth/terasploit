import random
import re
from typing import ClassVar

from teralibs.tsf.pex.parser.graphml import from_file


class Shuffle:
    """PEX payload shuffle library."""

    FLOW_INSTRUCTIONS: ClassVar = {
        "x86": [
            "call",
            "jae",
            "jb",
            "jbe",
            "jc",
            "jcxz",
            "je",
            "jecxz",
            "jg",
            "jge",
            "jl",
            "jle",
            "jmp",
            "jna",
            "jnae",
            "jnb",
            "jnbe",
            "jnc",
            "jne",
            "jng",
            "jnge",
            "jnl",
            "jnle",
            "jno",
            "jnp",
            "jns",
            "jnz",
            "jo",
            "jp",
            "jpe",
            "jpo",
            "js",
            "jz",
        ],
        "x64": [
            "call",
            "jae",
            "jb",
            "jbe",
            "jc",
            "jcxz",
            "je",
            "jecxz",
            "jg",
            "jge",
            "jl",
            "jle",
            "jmp",
            "jna",
            "jnae",
            "jnb",
            "jnbe",
            "jnc",
            "jne",
            "jng",
            "jnge",
            "jnl",
            "jnle",
            "jno",
            "jnp",
            "jns",
            "jnz",
            "jo",
            "jp",
            "jpe",
            "jpo",
            "js",
            "jz",
            "jrcxz",
        ],
    }

    @classmethod
    def from_graphml_file(cls, file_path, arch=None, name=None):
        """Shuffles blocks and internal instruction chains extracted from a GraphML file."""
        graphml = from_file(file_path)
        if not graphml:
            raise RuntimeError("Graphml failed to load.")

        raw_blocks = {_id: node for _id, node in graphml.nodes.items() if node.attributes.get("type") == "block"}

        blocks = cls._create_path(raw_blocks, graphml.graphs[0].edges)
        blocks = [{"node": block, "instructions": cls._process_block(block)} for block in blocks]

        label_prefix = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(4))
        labeler = cls._make_labeler(label_prefix)

        source_lines, labeled, label_refs = cls._render_blocks(blocks, labeler, arch)

        if not all(address in labeled for address in label_refs):
            raise ValueError("Missing label reference: shuffled branch points to unmapped block alignment.")

        if name is not None:
            source_lines = [f"{name}:"] + [" " * 16 + f"{line}" for line in source_lines]

        return "\n".join(source_lines) + "\n"

    @staticmethod
    def _make_labeler(label_prefix):
        """Returns a closure generating a structured localized position string label."""

        def labeler(address):
            return f"loc_{label_prefix}{address:04x}"

        return labeler

    @classmethod
    def _render_blocks(cls, blocks, labeler, arch):
        """Renders source lines for all blocks, tracking labeled addresses and branch targets."""
        source_lines = []
        labeled = []
        label_refs = []

        for block in blocks:
            address = block["node"].attributes["address"]
            source_lines.append(f"{labeler(address)}:")
            labeled.append(address)

            instructions, refs = cls._render_instructions(block["instructions"], labeler, arch)
            label_refs.extend(refs)
            source_lines.extend(f"    {inst}" for inst in instructions)

        return source_lines, labeled, label_refs

    @classmethod
    def _render_instructions(cls, nodes, labeler, arch):
        """Translates a block's instruction nodes into source lines, resolving flow branches."""
        instructions = []
        label_refs = []

        for node in nodes:
            src_text = node.attributes["instruction.source"].strip()
            flow_match = cls._match_flow_instruction(src_text, arch)

            if flow_match:
                mnemonic, address = flow_match
                instructions.append(f"{mnemonic} {labeler(address)}")
                label_refs.append(address)
            elif arch in ["x86", "x64"]:
                instructions.append(cls._to_db_directive(node.attributes["instruction.hex"]))
            else:
                instructions.append(src_text)

        return instructions, label_refs

    @classmethod
    def _match_flow_instruction(cls, src_text, arch):
        """Returns (mnemonic, address) if src_text is a relative control-flow branch, else None."""
        if arch not in cls.FLOW_INSTRUCTIONS:
            return None
        match = re.match(r"^(?P<mnemonic>\S+)\s+(?P<address>0x[a-f0-9]+)$", src_text)
        if not match or match.group("mnemonic") not in cls.FLOW_INSTRUCTIONS[arch]:
            return None
        return match.group("mnemonic"), int(match.group("address"), 16)

    @staticmethod
    def _to_db_directive(hex_str):
        """Converts a raw instruction hex string into a `db` byte-directive line."""
        hex_str = hex_str.strip()
        hex_bytes = [f"0x{hex_str[i : i + 2]}" for i in range(0, len(hex_str), 2)]
        return "db " + ", ".join(hex_bytes)

    @classmethod
    def _process_block(cls, block):
        """Extracts and topologically sorts instructions inside a generic basic block node wrapper."""
        subgraph = block.subgraph
        instructions = {_id: node for _id, node in subgraph.nodes.items() if node.attributes.get("type") == "instruction"}
        return cls._create_path(instructions, subgraph.edges)

    @classmethod
    def _create_path(cls, nodes, edges):
        """Performs a randomized Kahn-variant topological sort algorithm."""
        path = []
        targets = {edge.target for edge in edges}
        choices = [node for node in nodes.values() if node.id not in targets]

        while choices:
            selection = random.choice(choices)
            choices.remove(selection)

            if selection in path:
                continue

            path.append(selection)
            successors = [nodes[edge.target] for edge in selection.target_edges() if edge.target in nodes]

            for successor in successors:
                if successor in path:
                    continue

                all_sources_in_path = all(nodes.get(edge.source) in path for edge in successor.source_edges() if edge.source in nodes)

                if not all_sources_in_path:
                    continue

                if successor not in choices:
                    choices.append(successor)

        if len(path) != len(nodes):
            missing = [node.id for node in nodes.values() if node not in path]
            raise RuntimeError(f"Topological sort incomplete. Processed {len(path)} of {len(nodes)} nodes. Missing: {missing}")

        return path

    def __repr__(self) -> str:
        """Returns a string representation of the container and its attributes."""
        return f"{self.__class__.__name__}(library=Shuffle)"
