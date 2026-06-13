SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RULE_EXPLAINERS = {
    "FLOATING_VERSION": "Dependency version is not pinned exactly. Pin exact versions to reduce supply-chain drift.",
    "UNTRUSTED_INDEX": "Dependency source/registry is not in allowed registries. Use only trusted registries.",
    "DENY_PACKAGE": "Dependency is explicitly denied by policy denylist.",
    "MISSING_LOCKFILE": "Manifest exists but lockfile is missing while lockfiles are required.",
    "KNOWN_VULNERABILITY": "Package/version matches a known vulnerability from configured intelligence sources.",
    "TYPOSQUATTING_RISK": "Package name appears similar to protected/high-value packages and may be typosquatting.",
    "PACKAGE_TOO_NEW": "Package is newer than configured minimum age threshold.",
    "PUBLISHER_CHURN": "Publisher/owner changed too frequently in the configured time window.",
    "MAINTAINER_CHANGE_RISK": "Maintainer ownership changed beyond configured threshold.",
}
