from collections.abc import Sequence

from teralibs.terasploit.framework.console.package import DATASTORE as _DATASTORE, Option
from teralibs.terasploit.framework.options.storage import OPTION_REGISTRY
from teralibs.terasploit.framework.options.validators import OptionType


# Mixin class for module base


class Base:
    """The very base of all Terasploit Modules."""

    #: Global datastore reference for all modules to access configuration and state.
    DATASTORE = _DATASTORE

    #: Keys added via :meth:register_options are appended automatically.
    OPTIONS: Sequence = []

    #: Keys of options shown by show advanced.
    ADVANCED_OPTIONS: Sequence = []

    #: Keys of options shown by show evasion.
    EVASION_OPTIONS: Sequence = []

    #: Shortcuts as instance attributes
    opt = Option
    otype = OptionType

    @staticmethod
    def _option_keys(lst):
        """Return the set of uppercase key strings in a mixed str/Option list."""
        keyset = set()

        for e in lst:
            if isinstance(e, Option):
                keyset.add(e.key)

            elif isinstance(e, str):
                keyset.add(e.upper())

            elif isinstance(e, tuple):
                keyset.add(e[0].upper())

            else:
                raise KeyError(f"Unexpected item in OPTIONS list: {e!r} ({type(e).__name__}) - skipping.")

        return keyset

    # For consistency, we will disable invalid-name for this file.
    # pylint: disable=invalid-name

    def register_options(self, options):
        """
        Register normal options into the global registry and
        append their keys into this module instance.
        """
        self.OPTIONS = [*self.OPTIONS]
        existing = self._option_keys(self.OPTIONS)

        for opt in options:
            OPTION_REGISTRY[opt.key] = opt
            if opt.key not in existing:
                self.OPTIONS.append(opt.key)
                existing.add(opt.key)

    def register_advanced_options(self, options):
        """
        Register advanced options into the global registry and
        append their keys into this module instance.
        """
        self.ADVANCED_OPTIONS = [*self.ADVANCED_OPTIONS]
        existing = self._option_keys(self.ADVANCED_OPTIONS)

        for opt in options:
            OPTION_REGISTRY[opt.key] = opt
            if opt.key not in existing:
                self.ADVANCED_OPTIONS.append(opt.key)
                existing.add(opt.key)

    def register_evasion_options(self, options):
        """
        Register evasion options into the global registry and
        append their keys into this module instance.
        """
        self.EVASION_OPTIONS = [*self.EVASION_OPTIONS]
        existing = self._option_keys(self.EVASION_OPTIONS)

        for opt in options:
            OPTION_REGISTRY[opt.key] = opt
            if opt.key not in existing:
                self.EVASION_OPTIONS.append(opt.key)
                existing.add(opt.key)
