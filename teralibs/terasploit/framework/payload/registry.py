from teralibs.tsf.base.payload import ADAPTER, ALL_PAYLOAD_TYPES, SINGLE, STAGE, STAGER


def get_payload_type(payload_obj):
    """Return the normalised PAYLOAD_TYPE of *payload_obj*."""
    raw = getattr(payload_obj, "PAYLOAD_TYPE", SINGLE)
    normalised = str(raw).lower().strip()
    return normalised if normalised in ALL_PAYLOAD_TYPES else SINGLE


def is_single(payload_obj):
    """Return True when *payload_obj* is a self-contained single payload."""
    return get_payload_type(payload_obj) == SINGLE


def is_stager(payload_obj):
    """Return True when *payload_obj* is a stager with a companion stage."""
    return get_payload_type(payload_obj) == STAGER


def is_stage(payload_obj):
    """Return True when *payload_obj* is a second-stage module."""
    return get_payload_type(payload_obj) == STAGE


def is_adapter(payload_obj):
    """Return True when *payload_obj* is a single-wrapping adapter."""
    return get_payload_type(payload_obj) == ADAPTER


def get_stage_path(payload_obj):
    """Return STAGE_PATH from a stager module, or an empty string."""
    return str(getattr(payload_obj, "STAGE_PATH", "") or "").strip()


def get_wrapped_payload_path(payload_obj):
    """Return WRAPPED_PAYLOAD_PATH from an adapter module, or an empty string."""
    return str(getattr(payload_obj, "WRAPPED_PAYLOAD_PATH", "") or "").strip()


def describe(payload_obj):
    """Return a human-readable type label for *payload_obj*."""
    ptype = get_payload_type(payload_obj)
    labels = {
        SINGLE: "single (self-contained)",
        STAGER: f"stager -> stage: {get_stage_path(payload_obj) or '(unset)'}",
        STAGE: "stage",
        ADAPTER: f"adapter wrapping {get_wrapped_payload_path(payload_obj) or '(unset)'}",
    }
    return labels.get(ptype, ptype)
