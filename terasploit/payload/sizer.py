import contextlib
from dataclasses import dataclass, field


#: How many bytes over PAYLOAD_SPACE the framework will still tolerate.
#: Set to 0 for a hard limit with zero tolerance.
OVERAGE_HARD_LIMIT = 0


@dataclass
class SizeCheckResult:
    """Outcome of a payload size validation."""

    ok: bool
    generated: int
    max_size: int | None = None
    payload_space: int | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def __bool__(self):
        """Allow if result: as a shorthand for if result.ok:."""
        return self.ok

    def summary(self):
        """Return a one-line human-readable size summary."""
        parts = [f"size={self.generated:,} bytes"]
        if self.payload_space is not None:
            parts.append(f"space={self.payload_space:,}")

        if self.max_size is not None:
            parts.append(f"max={self.max_size:,}")

        return "  ".join(parts)


class PayloadSizeChecker:
    """Validates a generated payload's byte length against both MAX_SIZE and PAYLOAD_SPACE constraints."""

    def check(self, raw_bytes, payload_obj, module_obj=None):
        """Run all size checks and return a :class:SizeCheckResult."""
        generated = len(raw_bytes)
        max_size = self.read_int(payload_obj, "MAX_SIZE")
        payload_space = self.read_int(module_obj, "PAYLOAD_SPACE")

        warnings = []
        errors = []

        if max_size is not None and generated > max_size:
            errors.append(
                f"Payload size {generated:,} bytes exceeds MAX_SIZE "
                f"({max_size:,} bytes) declared by the payload module.  "
                "The payload is internally inconsistent."
            )

        if payload_space is not None:
            if generated > payload_space:
                overage = generated - payload_space
                if overage > OVERAGE_HARD_LIMIT:
                    # Hard block - payload will not fit in the delivery buffer.
                    errors.append(
                        f"Payload size {generated:,} bytes exceeds exploit "
                        f"PAYLOAD_SPACE ({payload_space:,} bytes) by "
                        f"{overage:,} bytes.  The payload will not fit in "
                        "the delivery buffer."
                    )
                else:
                    # Soft warning - within tolerance.
                    warnings.append(
                        f"Payload size {generated:,} bytes is {overage:,} byte(s) "
                        f"over PAYLOAD_SPACE ({payload_space:,} bytes) but within "
                        f"the {OVERAGE_HARD_LIMIT}-byte tolerance."
                    )
            elif generated == payload_space:
                # Exact fit - no room for alignment padding.
                warnings.append(
                    f"Payload exactly fills PAYLOAD_SPACE ({payload_space:,} "
                    "bytes).  No room for alignment padding - verify the exploit "
                    "can handle this."
                )

        if max_size is not None and payload_space is not None and max_size < payload_space:
            warnings.append(
                f"Exploit PAYLOAD_SPACE ({payload_space:,}) is larger than "
                f"payload MAX_SIZE ({max_size:,}).  The space declaration on "
                "the exploit module may be overly generous."
            )

        return SizeCheckResult(
            ok=len(errors) == 0,
            generated=generated,
            max_size=max_size,
            payload_space=payload_space,
            warnings=warnings,
            errors=errors,
        )

    @staticmethod
    def read_int(obj, attr):
        """Read an integer class attribute from *obj*, returning None on any failure."""
        if obj is None:
            return None

        val = getattr(obj, attr, None)
        if val is None:
            return None

        with contextlib.suppress(TypeError, ValueError):
            return int(val)
