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
    """
    Multi-scope key-value store for framework, module, payload,
    advanced, evasion, and encoder settings.
    """

    def __init__(self):
        self._defs = {scope: {} for scope in _VALID_SCOPES}
        self._vals = {scope: {} for scope in _VALID_SCOPES}

    def _require_scope(self, scope):
        """Raise ValueError when *scope* is not recognised."""
        if scope not in _VALID_SCOPES:
            valid = ", ".join(sorted(_VALID_SCOPES))
            raise ValueError(f"Unknown scope {scope!r}. Valid scopes: {valid}")

    def _resolve_scopes(self, scope):
        """Return the search order for a lookup operation."""
        if scope is not None:
            self._require_scope(scope)
            return (scope,)

        return _SCOPE_SEARCH_ORDER

    def register(self, scope, options):
        """Add a list of Option objects to the given scope."""
        self._require_scope(scope)

        defs = self._defs[scope]
        vals = self._vals[scope]

        for opt in options:
            defs[opt.key] = opt
            vals[opt.key] = opt.default

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

    def set(
        self,
        name,
        value,
        scope=None,
    ):
        """Assign *value* to the option identified by *name*."""
        key = name.upper()

        for sc in self._resolve_scopes(scope):
            if key in self._vals[sc]:
                self._vals[sc][key] = value
                return True

        return False

    def get(self, name, scope=None) -> Any:
        """Return the current value of *name*, or None if not found."""
        key = name.upper()

        for sc in self._resolve_scopes(scope):
            if key in self._vals[sc]:
                return self._vals[sc][key]

        return None

    def all(self, scope):
        """Return a snapshot dictionary of all current values in *scope*."""
        self._require_scope(scope)
        return dict(self._vals[scope])

    def definitions(self, scope):
        """Return a snapshot dictionary of all Option descriptors in *scope*."""
        self._require_scope(scope)
        return dict(self._defs[scope])

    def missing_required(self, scope):
        """
        Return a list of upper-cased names for required options whose
        current value is unset.
        """
        self._require_scope(scope)

        return [name for name, opt in self._defs[scope].items() if opt.required and self._vals[scope].get(name) is None]

    def clear_scope(self, scope):
        """Remove all definitions and values from *scope*."""
        self._require_scope(scope)

        self._defs[scope].clear()
        self._vals[scope].clear()


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

__all__ = [
    "DATASTORE",
    "OPTION_REGISTRY",
    "Option",
    "OptionType",
]
