import dataclasses
import re
from dataclasses import field


@dataclasses.dataclass
class FingerprintOptions:
    """Caller-supplied fingerprint validation config."""

    patterns: list[re.Pattern[str]]
    uri: str = "/"
    method: str = "GET"


class FingerprintError(Exception):
    """Base class for fingerprint validation failures."""


class FingerprintMismatch(FingerprintError):
    """Signature did not match a required pattern."""


class FingerprintUnreachable(FingerprintError):
    """Target did not respond to the fingerprinting request."""


@dataclasses.dataclass
class HttpFingerprint:
    """
    Structured fingerprint extracted from an HTTP response.

    Header keys are normalized:
        'Set-Cookie'       -> 'header_set_cookie'
        'WWW-Authenticate' -> 'header_www_authenticate'
    """

    # http_report = (method, code)
    http_report: tuple[str, str]
    uri: str
    server_port: int
    message: str
    signature: str
    content: str
    headers: dict[str, str] = field(default_factory=dict)
