import ipaddress
import os
import re
import urllib.parse
from collections import namedtuple
from enum import StrEnum

from teralibs.tsf.utils.exception import UrlParseError


ValidationResult = namedtuple("ValidationResult", ("ok", "reason"))

_OK = ValidationResult(ok=True, reason="")

# Constants

# Allowed URL schemes for safe URL validation (security whitelist)
_ALLOWED_SCHEMES = frozenset({"http", "https", "ftp", "ftps"})

# Regex pattern that blocks null bytes in filesystem paths (prevents injection/security issues)
_FORBIDDEN_PATH_CHARS_RE = re.compile(r"[\x00]")

# Set of accepted string values that represent boolean True
_TRUTHY = frozenset({"true", "yes", "1", "on"})

# Set of accepted string values that represent boolean False
_FALSY = frozenset({"false", "no", "0", "off"})

# Combined set of all valid boolean string representations (used for validation lookup)
_BOOL_VALUES = _TRUTHY | _FALSY

# Regex for validating hostnames:
# - Validates DNS-style domain names (e.g., example.com, api.example.com)
# - Enforces RFC-like label rules:
#   * each label must start and end with an alphanumeric character
#   * hyphens allowed only in the middle of a label
#   * maximum of 63 characters per label
# - Supports multi-level subdomains (e.g., a.b.c.example.com)
# - Enforces valid top-level domain format (2-63 alphabetic characters)
# - Allows "localhost" as a special-case development hostname
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"  # total length limit (DNS max)
    r"(?:"
    r"[a-zA-Z0-9]"  # start with alphanumeric
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"  # middle + end rules per label
    r"\.)+"  # dot-separated labels
    r"[a-zA-Z]{2,63}"  # TLD rules
    r"|localhost$"  # allow localhost
)


def _fail(msg):
    """Construct a failed ValidationResult with the given reason message."""
    return ValidationResult(ok=False, reason=msg)


class OptionType(StrEnum):
    """Namespace of string constants that identify each supported option type."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    PORT = "port"
    ADDRESS = "address"
    URL = "url"
    PATH = "path"
    BOOL = "bool"
    ENUM = "enum"


def _validate_string(value):
    """Any non-empty string passes."""
    if not isinstance(value, str) or not value.strip():
        return _fail("Expected a non-empty string value.")
    return _OK


def _validate_integer(value):
    """Accept any string that represents a whole number."""
    try:
        int(str(value).strip())
        return _OK

    except TypeError, ValueError:
        return _fail(f"Expected an integer (whole number), got: {value!r}")


def _validate_float(value):
    """Accept any string parseable as a Python float."""
    try:
        float(str(value).strip())
        return _OK

    except TypeError, ValueError:
        return _fail(f"Expected a numeric value (integer or decimal), got: {value!r}")


def _validate_port(value):
    """Accept integers in the TCP/UDP port range 1-65535."""
    try:
        port = int(str(value).strip())

    except TypeError, ValueError:
        return _fail(f"Port must be an integer, got: {value!r}")

    if not 1 <= port <= 65535:
        return _fail(f"Port must be between 1 and 65535 (inclusive), got: {port}")
    return _OK


def _validate_address(value):
    """Accept IPv4 addresses, IPv6 addresses, or valid hostnames."""
    val = str(value).strip()

    try:
        ipaddress.ip_address(val)
        return _OK

    except ValueError:
        pass

    if val in ("0.0.0.0", "::", "::0"):
        return _OK

    if _HOSTNAME_RE.match(val):
        return _OK

    return _fail(f"Expected a valid IPv4 address, IPv6 address, or hostname, got: {value!r}")


def _validate_url(value):
    """Accept URLs whose scheme is one of http, https, ftp, or ftps."""
    val = str(value).strip()

    try:
        parsed = urllib.parse.urlparse(val)

    except UrlParseError:
        return _fail(f"Could not parse URL: {value!r}")

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        schemes = ", ".join(sorted(_ALLOWED_SCHEMES))
        return _fail(f"URL scheme {parsed.scheme!r} is not supported.  Allowed schemes: {schemes}")

    if not parsed.netloc:
        return _fail(f"URL must include a host (e.g. http://example.com/path), got: {value!r}")

    return _OK


def _validate_path(value):
    """Accept any syntactically valid filesystem path."""
    val = str(value)

    if _FORBIDDEN_PATH_CHARS_RE.search(val):
        return _fail("Path must not contain null bytes.")

    if not val.strip():
        return _fail("Path must not be empty.")

    try:
        os.path.normpath(val)

    except (TypeError, ValueError) as exc:
        return _fail(f"Invalid path: {exc}")

    return _OK


def _validate_bool(value):
    """Accept the canonical boolean strings: true/false, yes/no, 1/0, on/off."""
    if str(value).strip().lower() in _BOOL_VALUES:
        return _OK
    accepted = "true, false, yes, no, 1, 0, on, off"
    return _fail(f"Expected a boolean value ({accepted}), got: {value!r}")


def _validate_enum(value, choices):
    """Accept only values that appear in the *choices* collection (case-insensitive)."""
    if not choices:
        return _OK

    val_lower = str(value).strip().lower()
    choices_lower = [str(c).lower() for c in choices]

    if val_lower in choices_lower:
        return _OK

    pretty = ", ".join(str(c) for c in choices)
    return _fail(f"Value {value!r} is not one of the allowed choices: {pretty}")


_VALIDATORS = {
    OptionType.STRING: _validate_string,
    OptionType.INTEGER: _validate_integer,
    OptionType.FLOAT: _validate_float,
    OptionType.PORT: _validate_port,
    OptionType.ADDRESS: _validate_address,
    OptionType.URL: _validate_url,
    OptionType.PATH: _validate_path,
    OptionType.BOOL: _validate_bool,
    OptionType.ENUM: _validate_enum,
}


def validate(opt_type, value, choices=None):
    """Validate *value* against the constraints imposed by *opt_type*."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return _OK

    fn = _VALIDATORS.get(opt_type)
    if fn is None:
        return _OK

    if opt_type == OptionType.ENUM:
        return fn(value, choices or [])

    return fn(value)


def type_label(opt_type):
    """
    Return a short display label for the given type token.
    """
    labels = {
        OptionType.STRING: "string",
        OptionType.INTEGER: "integer",
        OptionType.FLOAT: "float",
        OptionType.PORT: "port",
        OptionType.ADDRESS: "address",
        OptionType.URL: "url",
        OptionType.PATH: "path",
        OptionType.BOOL: "bool",
        OptionType.ENUM: "enum",
    }
    return labels.get(opt_type, "")
