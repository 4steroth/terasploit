_WILDCARD_VALUES = frozenset({"all", "*", ""})


def _normalise(value):
    """Return a lowercase list of string tokens from *value*."""
    if value is None:
        return []

    if isinstance(value, str):
        tokens = [value.strip().lower()]

    elif isinstance(value, (list, tuple)):
        tokens = [str(v).strip().lower() for v in value]

    else:
        tokens = [str(value).strip().lower()]

    return [t for t in tokens if t]


def _is_wildcard(values):
    """Return True when *values* contains only wildcard tokens or is empty."""
    if not values:
        return True

    return all(v in _WILDCARD_VALUES for v in values)


class CompatibilityResult:
    """Outcome of a single payload compatibility check."""

    def __init__(self, compatible, reasons=None):
        self.compatible = compatible
        self.reasons = reasons or []

    def __bool__(self):
        return self.compatible

    def __repr__(self):
        return f"CompatibilityResult(compatible={self.compatible}, reasons={self.reasons!r})"


def payload_validate(module_obj, payload_obj):
    """Checks whether a payload module is compatible with the active exploit."""
    reasons = []

    module_arch = _normalise(getattr(module_obj, "ARCH", None))
    module_platform = _normalise(getattr(module_obj, "PLATFORM", None))
    payload_arch = _normalise(getattr(payload_obj, "ARCH", None))
    payload_platform = _normalise(getattr(payload_obj, "PLATFORM", None))

    if not _is_wildcard(module_arch) and not _is_wildcard(payload_arch) and payload_arch:
        overlap = set(module_arch) & set(payload_arch)
        if not overlap:
            reasons.append(f"Architecture mismatch: module supports {', '.join(module_arch)} but payload targets {', '.join(payload_arch)}.")

    if not _is_wildcard(module_platform) and not _is_wildcard(payload_platform) and payload_platform:
        overlap = set(module_platform) & set(payload_platform)
        if not overlap:
            reasons.append(f"Platform mismatch: module supports {', '.join(module_platform)} but payload targets {', '.join(payload_platform)}.")

    compat_fn = getattr(payload_obj, "compatible", None)
    if callable(compat_fn):
        cached_size = getattr(payload_obj, "CACHED_SIZE", -1)
        if not compat_fn(cached_size):
            reasons.append(
                "Payload compatibility check failed (payload.compatible() "
                "returned False). The wrapped payload may be too large for "
                "this adapter's delivery mechanism."
            )

    return CompatibilityResult(compatible=not reasons, reasons=reasons)
