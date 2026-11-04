# Internal helper


def _get(o, key, fallback=None):
    """
    Unified attribute/key accessor for dict and object option entries.
    """
    # Return value from dictionary
    if isinstance(o, dict):
        return o.get(key, fallback)

    # Return value from object
    if isinstance(o, object) and not isinstance(o, (str, int, float, list, dict, tuple)):
        return getattr(o, key, fallback)

    # Return raw value
    return o


# Public API


def opt_name(o):
    """Return the name field of a payload option object or dict."""
    return str(_get(o, "name", ""))


def opt_default(o):
    """Return the default value of a payload option object or dict."""
    return _get(o, "default", None)


def opt_required(o):
    """Return True when the option declares itself required."""
    return bool(_get(o, "required", False))


def opt_desc(o):
    """Return the human-readable description of a payload option."""
    return str(_get(o, "desc", ""))
