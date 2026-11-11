import struct
from collections.abc import Callable, Mapping
from typing import Any


_NUMERIC_FORMATS: Mapping[str, str] = {
    "uint8": "<B",
    "uint16v": "<H",
    "uint16n": ">H",
    "uint32v": "<I",
    "uint32n": ">I",
}


class CStructInstance:
    """Represents an instantiated or parsed structure packet."""

    def __init__(self, fields_def: list[list], restraints: list[list], values: dict[str, Any] | None = None):
        self._fields_def = fields_def
        self._restraints = restraints

        self._values = values or {}
        for field in self._fields_def:
            f_name = field[1]
            if f_name not in self._values:
                # Auto-instantiate template defaults so construction mirrors parse behavior.
                # Storing a bare CStructTemplate would make field access and to_bytes() fail.

                if field[0] == "template" and len(field) > 2 and isinstance(field[2], CStructTemplate):
                    self._values[f_name] = field[2].make_struct()
                else:
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
        """Compiles the object fields down to raw binary bytes."""
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
        """Resolve the nested Payload field into concrete bytes."""
        inner_payload = payload

        for field in self._fields_def:
            if field[0] != "template" or field[1] != "Payload":
                continue

            inner_template = kwargs.get("Payload", field[2])
            if not inner_template:
                continue

            if isinstance(inner_template, CStructInstance):
                inner_payload = inner_template.to_bytes(payload)

            elif isinstance(inner_template, bytes):
                inner_payload = inner_template

            elif isinstance(inner_template, CStructTemplate):
                inner_payload = inner_template(**kwargs).to_bytes(payload)

            elif callable(inner_template):
                result = inner_template(payload, **kwargs)
                if not isinstance(result, bytes):
                    raise TypeError(f"Payload macro returned {type(result).__name__}, expected bytes.")
                inner_payload = result

        return inner_payload

    def _apply_size_restraints(self, kwargs: dict, inner_payload: bytes) -> None:
        """Update length-tracking fields in kwargs based on size restraints."""
        for restraint in self._restraints:
            if len(restraint) < 2:
                continue

            source_field, target_field = restraint[0], restraint[1]
            if source_field == "Payload" and isinstance(inner_payload, bytes):
                kwargs[target_field] = len(inner_payload)

    def from_s(self, data: bytes):
        """Parses a raw buffer into this instance, overwriting its field values."""
        self.parse_from(bytes(data), 0)
        return self

    def parse_from(self, data: bytes, offset: int) -> int:
        """Parses fields starting at offset and returns the offset after the last one."""
        parsed: set[str] = set()

        for field in self._fields_def:
            f_type, f_name = field[0], field[1]

            if f_type in _NUMERIC_FORMATS:
                fmt = _NUMERIC_FORMATS[f_type]
                size = struct.calcsize(fmt)
                self._require(data, offset, size, f_name)
                self._values[f_name] = struct.unpack_from(fmt, data, offset)[0]
                offset += size

            elif f_type == "template" and f_name != "Payload":
                nested = field[2].make_struct()
                offset = nested.parse_from(data, offset)
                self._values[f_name] = nested

            elif f_type in ("string", "template"):
                size = self._resolve_size(field, parsed, len(data) - offset)
                self._require(data, offset, size, f_name)
                self._values[f_name] = data[offset : offset + size]
                offset += size

            else:
                raise NotImplementedError(f"Field '{f_name}': unsupported type '{f_type}'")

            parsed.add(f_name)
        return offset

    def _size_sources(self) -> dict[str, tuple[str, Any]]:
        """Maps each bidirectional restraint source to (size field, optional adjust callable)."""
        return {r[0]: (r[1], r[2]) for r in self._restraints if len(r) >= 4 and r[3]}

    def _resolve_size(self, field: list, parsed: set[str], remaining: int) -> int:
        """Resolve a field's size: fixed, restraint-derived, trailing, or zero."""
        f_type, f_name = field[0], field[1]
        fixed = field[2] if len(field) > 2 else None

        if f_type == "string" and isinstance(fixed, int):
            return fixed

        size_sources = self._size_sources()
        if f_name in size_sources:
            size_field, adjust = size_sources[f_name]
            if size_field not in parsed:
                raise ValueError(f"Field '{f_name}' is sized by '{size_field}', which is defined after it")

            size = self._values[size_field]
            return adjust(size) if isinstance(adjust, Callable) else size

        return remaining if field is self._fields_def[-1] else 0

    @staticmethod
    def _require(data: bytes, offset: int, size: int, name: str) -> None:
        available = len(data) - offset
        if size > available:
            raise ValueError(f"Truncated buffer: field '{name}' needs {size} bytes at offset {offset}, {available} available")

    def _serialize_fields(self, kwargs: dict, inner_payload: bytes) -> bytes:
        """Pack numeric, template, and string fields into a concrete byte stream."""
        packed_bytes = b""

        for field in self._fields_def:
            f_type, f_name = field[0], field[1]
            val = kwargs.get(f_name)

            if f_type in _NUMERIC_FORMATS:
                packed_bytes += struct.pack(_NUMERIC_FORMATS[f_type], val)

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
    """Generates stateful CStructInstance objects for data manipulation and serialization."""

    def __init__(self, *args: list):
        self.fields_def: list[list] = list(args)
        self._restraints: list[list] = []

    def create_restraints(self, *args: list):
        """Defines dynamic size constraints between fields, e.g. PayloadLen = len(Payload)"""
        self._restraints = list(args)
        return self

    def make_struct(self, **kwargs: Any) -> CStructInstance:
        """Creates and returns a concrete data instance representing the structure layout."""
        return CStructInstance(self.fields_def, self._restraints, kwargs)

    def __call__(self, **kwargs: Any) -> CStructInstance:
        """Calling the template creates an adjustable data instance."""
        return self.make_struct(**kwargs)
