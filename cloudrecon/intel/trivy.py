"""Parse Trivy JSON. CloudRecon does not invoke Trivy itself in demo mode."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from cloudrecon.models import Evidence, MatchStatus


class TrivyHit(BaseModel):
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None = None
    severity: str | None = None
    cvss: float | None = None
    status: str = ""
    primary_url: str = ""
    target: str = ""


def parse_trivy(payload: dict[str, Any]) -> list[TrivyHit]:
    hits: list[TrivyHit] = []
    for result in payload.get("Results") or []:
        target = str(result.get("Target") or "")
        for vuln in result.get("Vulnerabilities") or []:
            cvss = _score(vuln.get("CVSS") or {})
            hits.append(
                TrivyHit(
                    cve_id=str(vuln.get("VulnerabilityID", "")).upper(),
                    package_name=str(vuln.get("PkgName", "")),
                    installed_version=str(vuln.get("InstalledVersion", "")),
                    fixed_version=vuln.get("FixedVersion") or None,
                    severity=vuln.get("Severity"),
                    cvss=cvss,
                    status=str(vuln.get("Status") or ""),
                    primary_url=str(vuln.get("PrimaryURL") or ""),
                    target=target,
                )
            )
    return [hit for hit in hits if hit.cve_id and hit.package_name]


def trivy_status(hit: TrivyHit) -> MatchStatus:
    if hit.status.lower() in {"not_affected", "fixed_version_installed"}:
        return MatchStatus.NOT_AFFECTED
    if hit.cve_id:
        return MatchStatus.CONFIRMED
    return MatchStatus.UNKNOWN


def trivy_evidence(hit: TrivyHit) -> Evidence:
    return Evidence(
        source="trivy",
        advisory_id=hit.primary_url,
        detail=(
            f"Trivy reported {hit.cve_id} on {hit.package_name} {hit.installed_version} "
            f"in {hit.target or 'unknown target'} (status {hit.status or 'unspecified'}, "
            f"fixed {hit.fixed_version or 'unknown'})."
        ),
    )


def load_trivy_file(text: str) -> list[TrivyHit]:
    return parse_trivy(json.loads(text))


def _score(cvss: dict[str, Any]) -> float | None:
    for source in ("nvd", "redhat", "ghsa"):
        block = cvss.get(source) or {}
        for key in ("V3Score", "V2Score"):
            if block.get(key) is not None:
                return float(block[key])
    return None
