"""Package identity normalization.

Vendor advisories are matched on the distro package name. NVD CPE product names
use a small alias table so libssl3 can be enriched as openssl. Aliases never
override an exact vendor-package comparison.
"""

from __future__ import annotations

import re

from cloudrecon.models import PackageRecord

_ARCH_SUFFIX = re.compile(r"\.(amd64|arm64|noarch|x86_64|aarch64|i386)$", re.IGNORECASE)

PRODUCT_ALIASES = {
    "libssl3": "openssl",
    "libssl1.1": "openssl",
    "openssl": "openssl",
    "openssl-libs": "openssl",
    "openssh-server": "openssh",
    "openssh-client": "openssh",
    "openssh": "openssh",
    "apache2": "apache-http-server",
    "httpd": "httpd",
    "log4j-core": "log4j-core",
    "nginx": "nginx",
    "curl": "curl",
}


def normalize_package_name(name: str) -> str:
    cleaned = (name or "").strip().lower()
    return _ARCH_SUFFIX.sub("", cleaned)


def canonical_product(name: str) -> str:
    normalized = normalize_package_name(name)
    return PRODUCT_ALIASES.get(normalized, normalized)


def package_identity(package: PackageRecord) -> str:
    return normalize_package_name(package.name)


def version_key(package: PackageRecord) -> str:
    """Single comparison string in the package manager's native format."""
    manager = package.manager.lower()
    if manager in {"rpm", "yum", "dnf"}:
        epoch = package.epoch if package.epoch not in {"", "(none)", None} else "0"
        release = package.release or ""
        base = package.version
        if release and "-" not in base:
            base = f"{base}-{release}"
        if ":" not in base:
            return f"{epoch}:{base}" if epoch not in {"0", ""} else base
        return base
    return package.version
