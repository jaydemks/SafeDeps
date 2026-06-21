from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from safedeps.models import Finding
from safedeps.scanners.metadata_signals import (
    MetadataSignals,
    age_finding,
    churn_finding,
    download_anomaly_finding,
    maintainer_change_finding,
    repository_link_finding,
)
from safedeps.scanners.typosquat import typosquat_finding


@dataclass(frozen=True)
class PackageVerificationContext:
    manager: str
    package: str
    file_ref: str
    signals: MetadataSignals


class Verifier(Protocol):
    name: str

    def verify(self, policy, context: PackageVerificationContext) -> list[Finding]:
        ...


class SupplyChainSignalVerifier:
    name = "supply-chain-signals"

    def verify(self, policy, context: PackageVerificationContext) -> list[Finding]:
        findings: list[Finding] = []
        for maybe_finding in (
            typosquat_finding(policy, context.manager, context.package, context.file_ref),
            age_finding(policy, context.manager, context.package, context.file_ref, context.signals),
            churn_finding(policy, context.manager, context.package, context.file_ref, context.signals),
            maintainer_change_finding(
                policy,
                context.manager,
                context.package,
                context.file_ref,
                context.signals,
            ),
            repository_link_finding(policy, context.manager, context.package, context.file_ref, context.signals),
            download_anomaly_finding(policy, context.manager, context.package, context.file_ref, context.signals),
        ):
            if maybe_finding:
                findings.append(maybe_finding)
        return findings


DEFAULT_VERIFIERS: tuple[Verifier, ...] = (SupplyChainSignalVerifier(),)


def verify_package(
    policy,
    manager: str,
    package: str,
    file_ref: str,
    signals: MetadataSignals,
    verifiers: tuple[Verifier, ...] = DEFAULT_VERIFIERS,
) -> list[Finding]:
    context = PackageVerificationContext(
        manager=manager,
        package=package,
        file_ref=file_ref,
        signals=signals,
    )
    findings: list[Finding] = []
    for verifier in verifiers:
        findings.extend(verifier.verify(policy, context))
    return findings
