import importlib.util

from teralibs.terasploit.framework.services import tables as tbl
from teralibs.tsf.utils.exception import ModuleInspectionError


# Path / name helpers


def _to_path(dotted):
    """Convert a dotted module name to its human-readable slash form."""
    return dotted.replace(".", "/")


def _category_of(dotted):
    """Return the leading category segment of a dotted module name."""
    return dotted.split(".")[0] if "." in dotted else dotted


# Compatibility helpers


def _normalise_list(value):
    """Coerce an ARCH or PLATFORM class attribute to a normalised frozenset."""
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value.lower().strip()})
    try:
        return frozenset(str(v).lower().strip() for v in value)
    except TypeError:
        return frozenset()


def _is_compatible(module_obj, candidate_cls, category):
    """Return True when *candidate_cls* is compatible with the active *module_obj*."""
    mod_arch = _normalise_list(getattr(module_obj, "ARCH", ["all"]))
    mod_platform = _normalise_list(getattr(module_obj, "PLATFORM", ["all"]))
    cand_arch = _normalise_list(getattr(candidate_cls, "ARCH", ["all"]))
    cand_plat = _normalise_list(getattr(candidate_cls, "PLATFORM", ["all"]))

    # "all" on either side is a wildcard - always matches.
    arch_ok = "all" in mod_arch or "all" in cand_arch or bool(mod_arch & cand_arch)

    if not arch_ok:
        return False

    if category == "encoder":
        # Encoders are not platform-gated.
        return True

    plat_ok = "all" in mod_platform or "all" in cand_plat or bool(mod_platform & cand_plat)
    return plat_ok


def _filter_compatible(
    module_paths,
    module_obj,
    category,
):
    """Filter *module_paths* to those compatible with the active *module_obj*."""
    compatible = []
    for dotted in module_paths:
        try:
            idx = tbl.Constants.module_index
            if idx is None:
                compatible.append(dotted)
                continue

            file_path = idx.get_path(dotted)
            if not file_path:
                compatible.append(dotted)
                continue

            spec = importlib.util.spec_from_file_location(dotted, file_path)
            if spec is None or spec.loader is None:
                compatible.append(dotted)
                continue

            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            cls = getattr(mod, "TerasploitModule", None)
            if cls is None:
                compatible.append(dotted)
                continue

            if _is_compatible(module_obj, cls, category):
                compatible.append(dotted)

        except ModuleInspectionError:
            compatible.append(dotted)

    return compatible
