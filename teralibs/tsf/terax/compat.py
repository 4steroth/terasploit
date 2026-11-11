from dataclasses import dataclass, field


# Maps each binary-container format to the OS platforms it can target.
_PLATFORM_REQUIRED = {
    "elf": frozenset({"linux"}),
    "elf-x64": frozenset({"linux"}),
    "elf-aarch64": frozenset({"linux"}),
    "exe": frozenset({"windows"}),
}

# Maps each binary-container format to the architectures it accepts.
# An empty frozenset would mean "any arch accepted" - not used here.
_ARCH_REQUIRED = {
    "elf": frozenset({"x64", "x86"}),
    "elf-x64": frozenset({"x64", "x86"}),
    "elf-aarch64": frozenset({"arm64", "aarch64"}),
    "exe": frozenset({"x64", "x86"}),
}

# Human-readable arch description used in error messages.
_ARCH_DISPLAY = {
    "elf": "x64 or x86",
    "elf-x64": "x64 or x86",
    "elf-aarch64": "arm64 / aarch64",
    "exe": "x64 or x86",
}

# Formats that impose an OS / arch constraint (everything else is text/raw).
_BINARY_CONTAINER_FORMATS = frozenset(_PLATFORM_REQUIRED)


@dataclass
class CompatResult:
    """Outcome of a single compatibility check."""

    ok: bool = True
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def check_compat(fmt, arch_list, platform_list):
    """Validate that *fmt* is compatible with the payload's declared arch and platform metadata."""
    result = CompatResult()

    # Text / transform formats are arch-agnostic - never flag them.
    if fmt not in _BINARY_CONTAINER_FORMATS:
        return result

    # raw is a binary kind but is a pure byte pass-through: no ELF/PE
    # container is built, so no ABI is imposed.
    if fmt == "raw":
        return result

    # Normalise to lowercase so payload constants like "Linux" or "ARM64"
    # compare cleanly against our lowercase table entries.
    arch_norm = [a.lower().strip() for a in arch_list if a]
    plat_norm = [p.lower().strip() for p in platform_list if p]

    generic_arch = not arch_norm
    generic_plat = not plat_norm

    # Platform check
    required_platforms = _PLATFORM_REQUIRED[fmt]

    if generic_plat:
        # No platform metadata - warn but allow.
        result.warnings.append(f"payload declares no PLATFORM; assuming compatible with '{fmt}' (requires: {', '.join(sorted(required_platforms))}).")

    elif not required_platforms.intersection(plat_norm):
        declared = ", ".join(plat_norm)
        needed = ", ".join(sorted(required_platforms))
        msg = f"Format '{fmt}' targets {needed} but payload platform is '{declared}'."

        result.errors.append(msg)
        result.ok = False

    # Arch check
    required_archs = _ARCH_REQUIRED[fmt]

    if generic_arch:
        # No arch metadata - warn but allow.
        result.warnings.append(f"payload declares no ARCH; assuming compatible with '{fmt}' (requires: {_ARCH_DISPLAY[fmt]}).")

    elif not required_archs.intersection(arch_norm):
        declared = ", ".join(arch_norm)
        msg = f"format '{fmt}' requires {_ARCH_DISPLAY[fmt]} shellcode but payload arch is '{declared}'."

        result.errors.append(msg)
        result.ok = False

    return result
