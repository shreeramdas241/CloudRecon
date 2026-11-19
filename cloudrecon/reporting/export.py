"""CSV and JSON exports of stored findings."""

from __future__ import annotations

import csv
import io
import json

from cloudrecon.models import FindingRecord


def findings_json(findings: list[FindingRecord]) -> str:
    return json.dumps([item.model_dump() for item in findings], indent=2, default=str)


def findings_csv(findings: list[FindingRecord]) -> str:
    buffer = io.StringIO()
    fields = [
        "cve_id", "asset_id", "asset_name", "region", "package_name", "installed_version",
        "fixed_version", "match_status", "confidence", "cvss", "severity", "kev",
        "priority_band", "priority_score", "remediation_status", "first_seen", "last_seen",
        "illustrative", "demo",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    for item in findings:
        writer.writerow({field: getattr(item, field) for field in fields})
    return buffer.getvalue()
