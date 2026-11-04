# engine.py - Internal ctypes bridge to libkeystone.so.
#
# terasm uses libkeystone.so as its assembler core.
# This module is internal infrastructure; import from terasm.assembler or
# terasm.cpu instead.

import contextlib
import inspect
import sys
from ctypes import (
    CFUNCTYPE,
    POINTER,
    byref,
    c_bool,
    c_char_p,
    c_int,
    c_size_t,
    c_ubyte,
    c_uint,
    c_uint64,
    c_void_p,
    cdll,
)
from os.path import exists, join, split
from platform import system as _platform

from teralibs.tsf.pex.terasm.assembler import TerasmError
from teralibs.tsf.pex.terasm.terasm_const import (
    TA_API_MAJOR,
    TA_ERR_OK,
)


# Shared library discovery
if not hasattr(sys.modules[__name__], "__file__"):
    # We ignore the error from this because it does not affect runtime behavior.
    # It is only used for locating the shared library.
    __file__ = inspect.getfile(inspect.currentframe())  # pyright: ignore

# `possibly-used-before-assignment` is a false positive here because the
# assignment is conditional on the `if` above.
_this_dir = split(__file__)[0]  # pylint: disable=E0606

# Candidate names in preference order. The .so is still named libkeystone
# because terasm wraps it without recompiling.
_LIB_CANDIDATES = (
    "keystone.dll",
    "libkeystone.so",
    f"libkeystone.so.{TA_API_MAJOR}",
    "libkeystone.dylib",
)

_LIB = None

# Co-located with this file (highest priority - project-local deployment)
for _name in _LIB_CANDIDATES:
    _path = join(_this_dir, _name)
    if exists(_path):
        try:
            _LIB = cdll.LoadLibrary(_path)
            break
        except OSError:
            pass

# System default paths
if _LIB is None:
    for _name in _LIB_CANDIDATES:
        try:
            _LIB = cdll.LoadLibrary(_name)
            break
        except OSError:
            pass

# /usr/local/lib/ (Linux / macOS non-system installs)
if _LIB is None and _platform() != "Windows":
    for _name in _LIB_CANDIDATES:
        _path = join("/usr/local/lib", _name)
        if exists(_path):
            try:
                _LIB = cdll.LoadLibrary(_path)
                break
            except OSError:
                pass

if _LIB is None:
    raise ImportError("terasm: could not load libkeystone.so. Ensure libkeystone.so is installed or placed alongside terasm/.")

# ctypes function prototypes

_kserr = c_int
_ksengine = c_void_p


def _proto(fname, restype, *argtypes):
    fn = getattr(_LIB, fname)
    fn.restype = restype
    fn.argtypes = argtypes


_proto("ks_version", c_uint, POINTER(c_int), POINTER(c_int))
_proto("ks_arch_supported", c_bool, c_int)
_proto("ks_open", _kserr, c_uint, c_uint, POINTER(_ksengine))
_proto("ks_close", _kserr, _ksengine)
_proto("ks_strerror", c_char_p, _kserr)
_proto("ks_errno", _kserr, _ksengine)
_proto("ks_option", _kserr, _ksengine, c_int, c_void_p)
_proto(
    "ks_asm",
    c_int,
    _ksengine,
    c_char_p,
    c_uint64,
    POINTER(POINTER(c_ubyte)),
    POINTER(c_size_t),
    POINTER(c_size_t),
)
_proto("ks_free", None, POINTER(c_ubyte))

# Callback type for the symbol-resolver option
TA_SYM_RESOLVER = CFUNCTYPE(c_bool, c_char_p, POINTER(c_uint64))


# Version query


def lib_version():
    """Return (major, minor, combined) from the loaded libkeystone.so."""
    if _LIB is None:
        raise RuntimeError("terasm: keystone library failed to load.")

    major = c_int()
    minor = c_int()
    combined = _LIB.ks_version(byref(major), byref(minor))
    return (major.value, minor.value, combined)


def arch_supported(arch):
    """Return True if the loaded library was compiled with support for arch."""
    if _LIB is None:
        raise RuntimeError("terasm: keystone library failed to load.")

    return bool(_LIB.ks_arch_supported(arch))


# Low-level handle operations (used by Assembler - not public API)


def open_engine(arch, mode):
    """
    Open a keystone engine handle for the given arch/mode pair.
    Returns the opaque handle (c_void_p).
    Raises TerasmError on failure.
    """
    if _LIB is None:
        raise RuntimeError("terasm: keystone library failed to load.")

    handle = _ksengine()
    status = _LIB.ks_open(arch, mode, byref(handle))
    if status != TA_ERR_OK:
        raise TerasmError(status)
    return handle


def close_engine(handle):
    """Close a keystone engine handle. Silent on error (destructor context)."""
    if _LIB is None:
        raise RuntimeError("terasm: keystone library failed to load.")

    with contextlib.suppress(Exception):
        _LIB.ks_close(handle)


def set_option(handle, opt, value):
    """Apply an engine option. Raises TerasmError on failure."""
    if _LIB is None:
        raise RuntimeError("terasm: keystone library failed to load.")

    status = _LIB.ks_option(handle, opt, value)
    if status != TA_ERR_OK:
        raise TerasmError(status)


def strerror(errno):
    """Return the human-readable string for an error code."""
    if _LIB is None:
        raise RuntimeError("terasm: keystone library failed to load.")

    msg = _LIB.ks_strerror(errno)
    if isinstance(msg, bytes):
        return msg.decode("utf-8")
    return msg


def get_errno(handle):
    """Return the last error code recorded on this engine handle."""
    if _LIB is None:
        raise RuntimeError("terasm: keystone library failed to load.")

    return _LIB.ks_errno(handle)


def assemble_raw(handle, source_bytes, addr):
    """
    Call ks_asm and return (byte_list, insn_count) on success.
    Raises TerasmError on failure.
    Returns (None, 0) when no instructions were assembled.
    """
    if _LIB is None:
        raise RuntimeError("terasm: keystone library failed to load.")

    encode = POINTER(c_ubyte)()
    encode_size = c_size_t()
    stat_count = c_size_t()

    status = _LIB.ks_asm(
        handle,
        source_bytes,
        addr,
        byref(encode),
        byref(encode_size),
        byref(stat_count),
    )

    if status != 0:
        errno = _LIB.ks_errno(handle)
        raise TerasmError(errno, stat_count.value)

    if stat_count.value == 0:
        return (None, 0)

    raw = bytes(bytearray(encode[i] for i in range(encode_size.value)))
    _LIB.ks_free(encode)
    return (raw, stat_count.value)
