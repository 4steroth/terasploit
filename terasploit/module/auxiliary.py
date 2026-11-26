from collections.abc import Sequence

from extension.module.base import Base
from libs.rank import Rank
from terasploit.module.intel import HostRecord


class Auxiliary(Base):
    """Base class for Terasploit auxiliary modules."""

    NAME: str
    DESCRIPTION: str
    AUTHOR: Sequence
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str
    RANK: str = Rank.NORMAL
    REFERENCES: Sequence
    ARCH: Sequence
    PLATFORM: Sequence
    AUXILIARY_MODE: Sequence

    def run(self, ctx):
        """Execute the auxiliary module."""

    def check(self, ctx):
        """Execute the check method of the auxiliary module."""

    def stop(self):
        """Optional teardown hook called when the module is unloaded."""

    def record_host(self, ctx, record):
        """Record a host and its associated services and findings."""
        if not isinstance(record, HostRecord):
            raise TypeError("record must be a HostRecord instance")

        intel = getattr(ctx, "_intel", None)
        if not intel:
            raise ValueError("There is no intel instance in auxiliary context, this is a framework level error")

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
