from typing import Any

from teralibs.terasploit.framework.options.default import (
    DRIVER_ADVANCED_OPTIONS,
    FRAMEWORK_CORE_OPTIONS,
    NETWORK_OPTIONS,
    PAYLOAD_ADVANCED_OPTIONS,
    PAYLOAD_EVASION_OPTIONS,
    PAYLOAD_OPTIONS,
    POST_MODULE_OPTIONS,
    REVERSE_TCP_ADVANCED_OPTIONS,
    STAGER_ADVANCED_OPTIONS,
    Option,
)
from teralibs.terasploit.framework.options.validators import (
    OptionType,
    ValidationResult,
    validate as _validate_value,
)


# Constants

_SCOPE_SEARCH_ORDER = (
    "module",
    "module_advanced",
    "payload",
    "payload_advanced",
    "module_evasion",
    "payload_evasion",
    "encoder",
    "framework",
)

_VALID_SCOPES = frozenset(_SCOPE_SEARCH_ORDER)


class OptionStorage:
    """Key-value store for framework, module, payload, advanced, evasion, and encoder settings."""

    def __init__(self):
        self._defs = {scope: {} for scope in _VALID_SCOPES}
        self._values: dict[str, Any] = {}

    def __getitem__(self, name: str) -> Any:
        return self._values.get(name.upper())

    def __setitem__(self, name: str, value: Any) -> None:
        self._values[name.upper()] = value

    def __contains__(self, name: str) -> bool:
        return name.upper() in self._values

    def _require_scope(self, scope):
        """Raise ValueError when *scope* is not recognised."""
        if scope not in _VALID_SCOPES:
            valid = ", ".join(sorted(_VALID_SCOPES))
            raise ValueError(f"Unknown scope {scope!r}. Valid scopes: {valid}")

    def _resolve_scopes(self, scope):
        """Return the search order for a definition lookup."""
        if scope is None:
            return _SCOPE_SEARCH_ORDER

        self._require_scope(scope)
        return (scope,)

    def register(self, scope, options):
        """Add a list of Option objects to the given scope."""
        self._require_scope(scope)

        defs = self._defs[scope]

        for opt in options:
            defs[opt.key] = opt
            if opt.key not in self._values:
                self._values[opt.key] = opt.default

    def validate(
        self,
        name,
        value,
        scope=None,
    ):
        """Validate *value* against the type constraint of the named option."""
        key = name.upper()

        for sc in self._resolve_scopes(scope):
            opt = self._defs[sc].get(key)

            if opt is not None and opt.opt_type is not None:
                return _validate_value(
                    opt.opt_type,
                    value,
                    choices=opt.choices,
                )

        return ValidationResult(ok=True, reason="")

    def set_value(self, name, value, scope=None):
        """Assign *value* to the option identified by *name*."""
        key = name.upper()

        if scope is not None:
            self._require_scope(scope)
            self._values[key] = value
            return True

        known = key in self._values or any(key in self._defs[sc] for sc in _VALID_SCOPES)
        if not known:
            return False

        self._values[key] = value
        return True

    def get_value(self, name) -> Any:
        """Return the current value of *name*, or None if not found."""
        return self._values.get(name.upper())

    def all_values(self, scope):
        """Return a snapshot dictionary of all current values in *scope*."""
        self._require_scope(scope)
        return {key: self._values.get(key) for key in self._defs[scope]}

    def definitions(self, scope):
        """Return a snapshot dictionary of all Option descriptors in *scope*."""
        self._require_scope(scope)
        return dict(self._defs[scope])

    def missing_required(self, scope):
        """Return a list of upper-cased names for required options whose current value is unset."""
        self._require_scope(scope)
        return [name for name, opt in self._defs[scope].items() if opt.required and self._values.get(name) is None]

    def clear_scope(self, scope):
        """Remove all definitions from *scope*."""
        self._require_scope(scope)

        keys = list(self._defs[scope].keys())
        self._defs[scope].clear()

        for key in keys:
            if not any(key in self._defs[other] for other in _VALID_SCOPES if other != scope):
                self._values.pop(key, None)


# Module-level singleton
DATASTORE = OptionStorage()

OPTION_REGISTRY = {
    opt.key: opt
    for option_set in (
        FRAMEWORK_CORE_OPTIONS,
        DRIVER_ADVANCED_OPTIONS,
        PAYLOAD_ADVANCED_OPTIONS,
        REVERSE_TCP_ADVANCED_OPTIONS,
        STAGER_ADVANCED_OPTIONS,
        PAYLOAD_EVASION_OPTIONS,
        POST_MODULE_OPTIONS,
        NETWORK_OPTIONS,
        PAYLOAD_OPTIONS,
    )
    for opt in option_set
}

__all__ = ["DATASTORE", "OPTION_REGISTRY", "Option", "OptionType"]
