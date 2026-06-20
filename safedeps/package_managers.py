from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from safedeps.models import Finding, PackageTarget
from safedeps.scanners import SCANNERS
from safedeps.scanners.base import Scanner


@dataclass(frozen=True)
class PackageManagerAdapter:
    scanner: Scanner

    @property
    def manager(self) -> str:
        return self.scanner.manager

    @property
    def manifests(self) -> tuple[str, ...]:
        return self.scanner.manifests

    @property
    def lockfiles(self) -> tuple[str, ...]:
        return self.scanner.lockfiles

    @property
    def supports_runtime_guard(self) -> bool:
        return self.scanner.supports_runtime_guard

    def scan(self, root: Path, policy) -> tuple[list[Finding], list[dict]]:
        return self.scanner.scan(root, policy)

    def component_from_target(self, target: PackageTarget) -> dict[str, str]:
        return self.scanner.component_from_target(target)


DEFAULT_PACKAGE_MANAGER_ADAPTERS: tuple[PackageManagerAdapter, ...] = tuple(
    PackageManagerAdapter(scanner) for scanner in SCANNERS
)


def adapters_by_manager(
    adapters: tuple[PackageManagerAdapter, ...] = DEFAULT_PACKAGE_MANAGER_ADAPTERS,
) -> dict[str, PackageManagerAdapter]:
    return {adapter.manager: adapter for adapter in adapters}
