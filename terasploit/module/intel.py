from dataclasses import dataclass, field


@dataclass(slots=True)
class ServiceRecord:
    """Represent a discovered network service."""

    port: int
    protocol: str = "tcp"
    name: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass(slots=True)
class FindingRecord:
    """Represent a discovered security finding."""

    name: str
    severity: str = "info"
    description: str | None = None
    evidence: str | None = None


@dataclass(slots=True)
class HostRecord:
    """Represent a discovered host and its associated intelligence."""

    address: str
    hostname: str | None = None
    platform: str | None = None
    arch: str | None = None
    services: list[ServiceRecord] = field(default_factory=list)
    findings: list[FindingRecord] = field(default_factory=list)
