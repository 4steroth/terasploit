from teralibs.tsf.terax.nops.registry import NOP_REGISTRY


class NopGenerator:
    """Resolve an architecture-specific generator and produce a NOP sequence."""

    @classmethod
    def architectures(cls):
        """Return the canonical architecture names supported by the registry."""
        return tuple(sorted({generator.name for generator in NOP_REGISTRY.values()}))

    @classmethod
    def strategies(cls):
        """Return available NOP strategies and defaults by canonical architecture."""
        result = {}
        for generator in sorted(set(NOP_REGISTRY.values()), key=lambda item: item.name):
            result[generator.name] = {
                "available": generator.available_strategies(),
                "default": generator.default_strategy,
            }
        return result

    @classmethod
    def default_strategy_for(cls, arch):
        """Return the default NOP strategy for an architecture or alias."""
        name = str(arch or "").strip().lower()
        generator = NOP_REGISTRY.get(name)
        if generator is None:
            return None
        return generator.default_strategy

    @classmethod
    def generate(cls, contents):
        """Generate an aligned NOP sequence for one explicitly selected architecture."""
        # Set default values for these variables
        badchars, byteorder, strategy = ((), None, None)

        length, arch, badchars, byteorder, strategy = contents
        if isinstance(arch, (list, tuple, set)):

            architectures = {str(item).strip().lower() for item in arch if item}
            if len(architectures) != 1:
                raise ValueError("NOP generation requires exactly one target architecture")
            arch = architectures.pop()

        else:
            arch = str(arch or "").strip().lower()

        if arch in ("armv7", "arm32"):
            raise ValueError(f"{arch!r} is ambiguous; select 'arm-a32', 'thumb', or 'thumb2' explicitly")

        if byteorder is None:
            if arch.endswith(("el", "le")):
                byteorder = "little"
            elif arch.endswith("be"):
                byteorder = "big"

        try:
            generator = NOP_REGISTRY[arch]

        except KeyError:
            raise ValueError(f"unsupported NOP architecture: {arch or '<unspecified>'}") from None

        return generator.generate(length, badchars, byteorder, strategy)


__all__ = ["NOP_REGISTRY", "NopGenerator"]
