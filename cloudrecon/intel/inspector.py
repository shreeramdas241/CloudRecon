"""Parse Amazon Inspector v2 findings. Live listing is optional and read-only."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class InspectorHit(BaseModel):
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None = None
    severity: str | None = None
    instance_id: str
    finding_arn: str = ""
    status: str = ""


def parse_inspector_findings(findings: list[dict[str, Any]]) -> list[InspectorHit]:
    hits: list[InspectorHit] = []
    for finding in findings:
        details = finding.get("packageVulnerabilityDetails") or {}
        cve = str(details.get("vulnerabilityId") or "")
        instance_id = ""
        for resource in finding.get("resources") or []:
            if resource.get("type") == "AWS_EC2_INSTANCE":
                instance_id = str(resource.get("id") or "")
                break
        for package in details.get("vulnerablePackages") or []:
            if not cve or not package.get("name"):
                continue
            hits.append(
                InspectorHit(
                    cve_id=cve.upper(),
                    package_name=str(package.get("name")),
                    installed_version=str(package.get("version") or ""),
                    fixed_version=package.get("fixedInVersion") or None,
                    severity=finding.get("severity"),
                    instance_id=instance_id,
                    finding_arn=str(finding.get("findingArn") or ""),
                    status=str(finding.get("status") or ""),
                )
            )
    return hits


def list_inspector_findings(client: Any, instance_ids: list[str]) -> list[dict[str, Any]]:
    """Read Inspector findings for specific instances. The client is injected."""
    if not instance_ids:
        return []
    paginator = client.get_paginator("list_findings")
    rows: list[dict[str, Any]] = []
    criteria = {"resourceId": [{"comparison": "EQUALS", "value": value} for value in instance_ids]}
    for page in paginator.paginate(filterCriteria=criteria):
        rows.extend(page.get("findings", []))
    return rows
