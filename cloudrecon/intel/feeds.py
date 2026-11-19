"""Load and parse NVD, OSV, KEV, and vendor advisory documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from cloudrecon.errors import IntelError


class VersionEvent(BaseModel):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None

    def as_dict(self) -> dict[str, str]:
        data: dict[str, str] = {}
        for key in ("introduced", "fixed", "last_affected"):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data


class Advisory(BaseModel):
    id: str
    source: str
    ecosystem: str
    package: str
    aliases: list[str] = Field(default_factory=list)
    cve_ids: list[str]
    events: list[VersionEvent]
    summary: str
    illustrative: bool = False
    cvss: float | None = None
    severity: str | None = None

    def package_names(self) -> set[str]:
        names = {self.package.lower(), *(alias.lower() for alias in self.aliases)}
        return names


class CpeMatch(BaseModel):
    product: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None


class NvdRecord(BaseModel):
    cve_id: str
    description: str = ""
    cvss: float | None = None
    severity: str | None = None
    illustrative: bool = False
    cpe_matches: list[CpeMatch] = Field(default_factory=list)


class KevRecord(BaseModel):
    cve_id: str
    vendor: str = ""
    product: str = ""
    name: str = ""
    date_added: str = ""
    ransomware_use: str = ""
    snapshot_note: str = ""


class IntelBundle(BaseModel):
    advisories: list[Advisory] = Field(default_factory=list)
    nvd: dict[str, NvdRecord] = Field(default_factory=dict)
    kev: dict[str, KevRecord] = Field(default_factory=dict)
    offline: bool = True
    notes: list[str] = Field(default_factory=list)


def load_intel_files(advisory_path: Path, nvd_path: Path, kev_path: Path) -> IntelBundle:
    advisories = _load_advisories(advisory_path)
    nvd = load_nvd_document(json.loads(nvd_path.read_text(encoding="utf-8")))
    kev = load_kev_document(json.loads(kev_path.read_text(encoding="utf-8")))
    return IntelBundle(
        advisories=advisories,
        nvd=nvd,
        kev=kev,
        offline=True,
        notes=[
            "Offline intelligence snapshots are a curated subset.",
            "CVE-9999-* records are synthetic. CVE-2021-44228 uses the published 2.15.0 fix boundary.",
            "Refresh NVD, OSV, vendor advisories, and the full CISA KEV catalog before operational use.",
        ],
    )


def _load_advisories(path: Path) -> list[Advisory]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("advisories") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise IntelError("Vendor advisory file must contain an advisories list")
    advisories: list[Advisory] = []
    for row in rows:
        events = [VersionEvent.model_validate(event) for event in row.get("events", [])]
        advisories.append(Advisory.model_validate({**row, "events": events}))
    return advisories


def load_kev_document(payload: dict[str, Any]) -> dict[str, KevRecord]:
    rows = payload.get("vulnerabilities")
    if not isinstance(rows, list):
        raise IntelError("KEV document has no vulnerabilities list")
    catalog: dict[str, KevRecord] = {}
    for row in rows:
        cve = str(row.get("cveID") or row.get("cve_id") or "").upper()
        if not cve:
            continue
        catalog[cve] = KevRecord(
            cve_id=cve,
            vendor=str(row.get("vendorProject") or row.get("vendor") or ""),
            product=str(row.get("product") or ""),
            name=str(row.get("vulnerabilityName") or row.get("name") or ""),
            date_added=str(row.get("dateAdded") or row.get("date_added") or ""),
            ransomware_use=str(row.get("knownRansomwareCampaignUse") or row.get("ransomware_use") or ""),
            snapshot_note=str(row.get("snapshot_note") or payload.get("snapshot_note") or ""),
        )
    return catalog


def load_nvd_document(payload: dict[str, Any]) -> dict[str, NvdRecord]:
    if "records" in payload:
        records = {}
        for row in payload["records"]:
            record = NvdRecord.model_validate(row)
            records[record.cve_id.upper()] = record
        return records
    if "vulnerabilities" in payload:
        return {item.cve_id: item for item in parse_nvd_api(payload)}
    raise IntelError("Unrecognized NVD snapshot shape")


def parse_nvd_api(payload: dict[str, Any]) -> list[NvdRecord]:
    records: list[NvdRecord] = []
    for wrapper in payload.get("vulnerabilities", []):
        cve = wrapper.get("cve") or wrapper
        cve_id = str(cve.get("id", "")).upper()
        if not cve_id:
            continue
        description = ""
        for item in cve.get("descriptions") or []:
            if item.get("lang") == "en":
                description = str(item.get("value", ""))
                break
        cvss, severity = _cvss(cve.get("metrics") or {})
        matches: list[CpeMatch] = []
        for config in cve.get("configurations") or []:
            for node in config.get("nodes") or []:
                for cpe in node.get("cpeMatch") or []:
                    if not cpe.get("vulnerable", False):
                        continue
                    product = _cpe_product(str(cpe.get("criteria", "")))
                    if not product:
                        continue
                    matches.append(
                        CpeMatch(
                            product=product,
                            version_start_including=cpe.get("versionStartIncluding"),
                            version_start_excluding=cpe.get("versionStartExcluding"),
                            version_end_including=cpe.get("versionEndIncluding"),
                            version_end_excluding=cpe.get("versionEndExcluding"),
                        )
                    )
        records.append(
            NvdRecord(
                cve_id=cve_id,
                description=description,
                cvss=cvss,
                severity=severity,
                cpe_matches=matches,
            )
        )
    return records


def parse_osv_vuln(vuln: dict[str, Any]) -> list[Advisory]:
    cves = [alias.upper() for alias in vuln.get("aliases") or [] if str(alias).upper().startswith("CVE-")]
    if str(vuln.get("id", "")).upper().startswith("CVE-"):
        cves.append(str(vuln["id"]).upper())
    cves = sorted(set(cves))
    if not cves:
        return []
    advisories: list[Advisory] = []
    for affected in vuln.get("affected") or []:
        package = (affected.get("package") or {}).get("name")
        ecosystem = (affected.get("package") or {}).get("ecosystem")
        if not package or not ecosystem:
            continue
        events: list[VersionEvent] = []
        for block in affected.get("ranges") or []:
            if block.get("type") not in {None, "ECOSYSTEM", "GIT"}:
                continue
            if block.get("type") == "GIT":
                continue
            for event in block.get("events") or []:
                events.append(VersionEvent.model_validate(event))
        short_name = package.split(":")[-1]
        advisories.append(
            Advisory(
                id=str(vuln.get("id", cves[0])),
                source="osv",
                ecosystem=str(ecosystem),
                package=short_name,
                aliases=[package, short_name],
                cve_ids=cves,
                events=events,
                summary=str(vuln.get("summary") or ""),
            )
        )
    return advisories


def _cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            if score is not None:
                return float(score), str(severity) if severity else None
    return None, None


def _cpe_product(criteria: str) -> str:
    parts = criteria.split(":")
    if len(parts) > 4:
        return parts[4].lower()
    return ""
