from teralibs.terasploit.framework.options.storage import (
    OPTION_REGISTRY,
    PAYLOAD_ADVANCED_OPTIONS,
    PAYLOAD_EVASION_OPTIONS,
)


def _get(o, key, fallback=None):
    """Unified attribute/key accessor for dict and object option entries."""
    if isinstance(o, dict):
        return o.get(key, fallback)
    if not isinstance(o, (str, int, float, list, tuple)):
        return getattr(o, key, fallback)
    return o


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


class OptionBuilder:
    """Builds and validates the resolved option dict for a payload module."""

    @staticmethod
    def build(payload_obj, overrides):
        """Merge option defaults and CLI overrides into a single resolved dict."""
        options = {}

        for o in getattr(payload_obj, "OPTIONS", None) or []:
            k = opt_name(o)
            # When o is a plain string, opt_default returns the key name itself;
            # fall back to OPTION_REGISTRY for the real default.
            v = opt_default(o)
            if v == k:
                registry_opt = OPTION_REGISTRY.get(k.upper())
                v = registry_opt.default if registry_opt else None
            if k and v is not None:
                options[k.upper()] = v

        for o in PAYLOAD_ADVANCED_OPTIONS:
            key = o.name.upper()
            if key not in options and o.default is not None:
                options[key] = o.default

        for o in getattr(payload_obj, "ADVANCED_OPTIONS", None) or []:
            k = opt_name(o)
            if k.upper() not in options:
                registry_opt = OPTION_REGISTRY.get(k.upper())
                if registry_opt and registry_opt.default is not None:
                    options[k.upper()] = registry_opt.default

        # Evasion defaults (EnableStageEncoding, EXITFUNC, etc.) must be seeded
        # here so the assembler can read them via ctx.get_option() even when the
        # operator has not explicitly set them.
        for o in PAYLOAD_EVASION_OPTIONS:
            key = o.name.upper()
            if key not in options and o.default is not None:
                options[key] = o.default

        options.update(overrides)
        return options

    @staticmethod
    def missing_required(payload_obj, options):
        """Return the names of required options that have no value in options."""
        missing = []
        for o in getattr(payload_obj, "OPTIONS", None) or []:
            name = opt_name(o)
            if name and opt_required(o) and not options.get(name.upper()) and not opt_default(o):
                missing.append(name)
        return missing
