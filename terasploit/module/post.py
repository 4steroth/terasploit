from collections.abc import Sequence

from extension.module.base import Base
from libs.rank import Rank
from terasploit.module.intel import HostRecord


class Post(Base):
    """Base class for Terasploit post-exploitation modules."""

    NAME: str
    DESCRIPTION: str
    AUTHOR: str | Sequence
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str
    RANK: str = Rank.NORMAL
    REFERENCES: Sequence
    ARCH: Sequence
    PLATFORM: Sequence
    SESSION_TYPES: Sequence

    def run(self, ctx):
        """Execute the post module against the active session."""

    def record_host(self, ctx, record):
        """Record a host and its associated services and findings."""
        if not isinstance(record, HostRecord):
            raise TypeError("record must be a HostRecord instance")

        intel = getattr(ctx, "_intel", None)
        if not intel:
            raise ValueError("There is no intel instance in post context, this is a framework level error")

        intel.add_host(
            record.address,
            hostname=record.hostname,
            platform=record.platform,
            architecture=record.arch,
        )

        for service in record.services:
            intel.add_service(
                record.address,
                service.protocol,
                service.port,
                name=service.name,
                product=service.product,
                version=service.version,
            )

        for finding in record.findings:
            intel.add_finding(
                record.address,
                finding.name,
                severity=finding.severity,
            )
