import struct
from typing import Any


class CStructInstance:
    """Represents an instantiated or parsed structure packet."""

    def __init__(self, fields_def: list[list], restraints: list[list], values: dict[str, Any] | None = None):
        self._fields_def = fields_def
        self._restraints = restraints
        self._values = values or {}

        # Initialize default values from the layout definition
        for field in self._fields_def:
            f_name = field[1]
            if f_name not in self._values:
                self._values[f_name] = field[2] if len(field) > 2 else None

    def __getattr__(self, name: str) -> Any:
        """Allows accessing fields via attribute syntax: pkt.Type"""
        if name in self._values:
            return self._values[name]
        raise AttributeError(f"'CStructInstance' object has no attribute '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        """Allows setting fields via attribute syntax: pkt.Type = 1"""
        if name.startswith("_"):
            super().__setattr__(name, value)
        else:
            self._values[name] = value

    def __getitem__(self, key: str) -> Any:
        """Allows accessing fields via dictionary syntax: pkt['Type']"""
        return self._values[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """Allows setting fields via dictionary syntax: pkt['Type'] = 1"""
        self._values[key] = value

    def to_bytes(self, payload: bytes = b"") -> bytes:
        """
        Compiles the object fields down to raw binary bytes.
        """
        kwargs = self._values.copy()

        # Evaluate nested layout templates/payloads first
        inner_payload = self._evaluate_inner_payload(payload, kwargs)

        # Update dynamic layout constraints (e.g., updating length fields)
        self._apply_size_restraints(kwargs, inner_payload)

        # Serialize all fields into a raw binary stream
        packed_bytes = self._serialize_fields(kwargs, inner_payload)

        # Fallback trailing payload append if no explicit Payload template was targeted
        if not any(f[0] == "template" and f[1] == "Payload" for f in self._fields_def):
            packed_bytes += payload

        return packed_bytes

    def _evaluate_inner_payload(self, payload: bytes, kwargs: dict) -> bytes:
        """
        Recursively processes nested structures, executes callable macros,
        or passes through raw bytes to resolve the definitive inner payload block.
        """
        inner_payload = payload
        for field in self._fields_def:
            if field[0] == "template" and field[1] == "Payload":
                inner_template = kwargs.get("Payload", field[2])
                if inner_template:
                    if isinstance(inner_template, CStructInstance):
                        inner_payload = inner_template.to_bytes(payload)
                    elif isinstance(inner_template, bytes):
                        inner_payload = inner_template  # Direct pass-through
                    elif callable(inner_template):
                        result = inner_template(payload, **kwargs)
                        if isinstance(result, bytes):
                            inner_payload = result
                        else:
                            raise TypeError(f"Payload macro returned {type(result).__name__}, expected bytes.")
        return inner_payload

    def _apply_size_restraints(self, kwargs: dict, inner_payload: bytes) -> None:
        """
        Updates dynamic structural variables in-place (e.g., mapping payload sizes
        back into specialized header fields) based on structural constraints.
        """
        for restraint in self._restraints:
            if len(restraint) >= 2:
                source_field, target_field = restraint[0], restraint[1]
                if source_field == "Payload" and isinstance(inner_payload, bytes):
                    kwargs[target_field] = len(inner_payload)

    def _serialize_fields(self, kwargs: dict, inner_payload: bytes) -> bytes:
        """
        Iterates over the field definitions to pack numeric primitives, templates,
        and strings into a concrete byte stream.
        """
        type_map = {
            "uint8": ("B", "<"),
            "uint16v": ("H", "<"),
            "uint16n": ("H", ">"),
            "uint32v": ("I", "<"),
            "uint32n": ("I", ">"),
        }
        packed_bytes = b""

        for field in self._fields_def:
            f_type, f_name = field[0], field[1]
            val = kwargs.get(f_name)

            if f_type in type_map:
                fmt_char, endian = type_map[f_type]
                packed_bytes += struct.pack(f"{endian}{fmt_char}", val)

            elif f_type == "template":
                if f_name == "Payload":
                    if isinstance(inner_payload, bytes):
                        packed_bytes += inner_payload
                elif isinstance(val, CStructInstance):
                    packed_bytes += val.to_bytes()

            elif f_type == "string":
                if isinstance(val, bytes):
                    packed_bytes += val
                elif isinstance(val, str):
                    packed_bytes += val.encode("utf-8")

        return packed_bytes


class CStructTemplate:
    """
    The blueprint definition class. Generates stateful CStructInstance
    objects for data manipulation and serialization.
    """

    def __init__(self, *args: list):
        self.fields_def: list[list] = list(args)
        self._restraints: list[list] = []

    def create_restraints(self, *args: list):
        """Defines dynamic size constraints between fields, e.g. PayloadLen = len(Payload)"""
        self._restraints = list(args)
        return self

    def make_struct(self, **kwargs: Any) -> CStructInstance:
        """
        Creates and returns a concrete data instance representing the structure layout.
        Allows passing optional variable overrides immediately.
        """
        return CStructInstance(self.fields_def, self._restraints, kwargs)

    def __call__(self, **kwargs: Any) -> CStructInstance:
        """
        Calling the template creates an adjustable data instance.
        Example: pkt = Constants.SMB_HDR(Command=0x72)
        """
        return self.make_struct(**kwargs)
