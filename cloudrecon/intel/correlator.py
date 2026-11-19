"""Correlate installed packages with vendor, NVD, KEV, Trivy, and Inspector data.

An exact ecosystem comparison from a vendor or OSV advisory outranks an NVD
upstream range. That is what prevents a patched distro revision from staying
vulnerable solely because its upstream version is inside an NVD window.
"""

from __future__ import annotations

from cloudrecon.intel.feeds import Advisory, IntelBundle
from cloudrecon.intel.inspector import InspectorHit
from cloudrecon.intel.ranges import bounds_match, describe_events, evaluate_events, fixed_version
from cloudrecon.intel.trivy import TrivyHit, trivy_evidence, trivy_status
from cloudrecon.models import CorrelationResult, Evidence, HostInventory, MatchStatus, PackageRecord
from cloudrecon.normalize import canonical_product, normalize_package_name, version_key
from cloudrecon.versioning import style_for_ecosystem, style_for_manager, upstream_version

_APP_ECOSYSTEMS = {"maven", "pypi", "npm", "application"}
_AUTHORITATIVE = {"vendor", "osv"}


def ecosystem_for_host(os_info: dict[str, str]) -> str:
    distro = (os_info.get("id") or "").lower()
    version = os_info.get("version_id") or ""
    if distro == "ubuntu":
        return f"Ubuntu:{version}"
    if distro == "debian":
        return f"Debian:{version}"
    if distro in {"amzn", "amazon", "amazonlinux"}:
        if version.startswith("2023"):
            return "AmazonLinux:2023"
        if version.startswith("2"):
            return "AmazonLinux:2"
        return f"AmazonLinux:{version}"
    if not distro:
        return ""
    return f"{distro}:{version}"


def correlate(
    host: HostInventory,
    intel: IntelBundle,
    trivy_hits: list[TrivyHit] | None = None,
    inspector_hits: list[InspectorHit] | None = None,
) -> list[CorrelationResult]:
    grouped: dict[tuple[str, str], list[CorrelationResult]] = {}
    host_ecosystem = ecosystem_for_host(host.os)
    for package in host.packages:
        for result in _from_advisories(package, intel, host_ecosystem):
            _add(grouped, result)
        for result in _from_nvd(package, intel):
            _add(grouped, result)
    known = {(normalize_package_name(pkg.name), version_key(pkg)) for pkg in host.packages}
    for hit in trivy_hits or []:
        result = _from_trivy(hit, known)
        if result is not None:
            _add(grouped, result)
    for hit in inspector_hits or []:
        result = _from_inspector(hit, known)
        if result is not None:
            _add(grouped, result)
    merged = [enrich_kev(_merge(items), intel) for items in grouped.values()]
    return sorted(merged, key=lambda item: (item.package_name, item.cve_id))


def _add(grouped: dict[tuple[str, str], list[CorrelationResult]], result: CorrelationResult) -> None:
    grouped.setdefault((result.package_name, result.cve_id), []).append(result)


def _from_advisories(package: PackageRecord, intel: IntelBundle, host_ecosystem: str) -> list[CorrelationResult]:
    results: list[CorrelationResult] = []
    installed_name = normalize_package_name(package.name)
    try:
        package_style = style_for_manager(package.manager)
        installed = version_key(package)
    except Exception:
        return []
    for advisory in intel.advisories:
        if installed_name not in advisory.package_names():
            continue
        if not _applies(advisory, host_ecosystem, package.manager):
            continue
        try:
            style = style_for_ecosystem(advisory.ecosystem)
        except Exception:
            continue
        if style != package_style:
            continue
        events = [event.as_dict() for event in advisory.events]
        outcome = evaluate_events(installed, events, style)
        status = {
            "affected": MatchStatus.CONFIRMED,
            "not_affected": MatchStatus.NOT_AFFECTED,
        }.get(outcome, MatchStatus.UNKNOWN)
        confidence = 0.9 if status != MatchStatus.UNKNOWN else 0.2
        source = "osv" if advisory.source == "osv" else "vendor"
        detail = (
            f"{advisory.id} ({advisory.ecosystem}) {advisory.summary} "
            f"Installed {installed} is {outcome.replace('_', ' ')} "
            f"for {describe_events(events) or 'an empty range'}."
        )
        if advisory.illustrative:
            detail = "ILLUSTRATIVE advisory, not a live vendor feed. " + detail
        for cve in advisory.cve_ids:
            results.append(
                CorrelationResult(
                    status=status,
                    confidence=confidence,
                    cve_id=cve.upper(),
                    package_name=installed_name,
                    installed_version=installed,
                    affected_versions=describe_events(events),
                    fixed_version=fixed_version(events),
                    sources=[source, advisory.source],
                    evidence=[
                        Evidence(
                            source=source,
                            advisory_id=advisory.id,
                            detail=detail,
                            illustrative=advisory.illustrative,
                        )
                    ],
                    cvss=advisory.cvss,
                    severity=advisory.severity,
                    version_style=style,
                )
            )
    return results


def _from_nvd(package: PackageRecord, intel: IntelBundle) -> list[CorrelationResult]:
    results: list[CorrelationResult] = []
    try:
        installed = version_key(package)
        upstream = upstream_version(installed, package.manager)
    except Exception:
        return results
    product = canonical_product(package.name)
    for record in intel.nvd.values():
        matched_ranges: list[str] = []
        affected = False
        for match in record.cpe_matches:
            if match.product not in {product, normalize_package_name(package.name)}:
                continue
            outcome = bounds_match(
                upstream,
                style="deb",
                start_including=match.version_start_including,
                start_excluding=match.version_start_excluding,
                end_including=match.version_end_including,
                end_excluding=match.version_end_excluding,
            )
            if outcome == "affected":
                affected = True
                matched_ranges.append(
                    " ".join(
                        part
                        for part in (
                            f">={match.version_start_including}" if match.version_start_including else "",
                            f">{match.version_start_excluding}" if match.version_start_excluding else "",
                            f"<={match.version_end_including}" if match.version_end_including else "",
                            f"<{match.version_end_excluding}" if match.version_end_excluding else "",
                        )
                        if part
                    )
                )
        if not affected:
            continue
        detail = (
            f"NVD lists {record.cve_id} against upstream {product} {upstream}. "
            "Distro revision and backport status are not decided by this match. "
            f"Range: {', '.join(matched_ranges)}."
        )
        if record.illustrative:
            detail = "ILLUSTRATIVE NVD snapshot row. " + detail
        results.append(
            CorrelationResult(
                status=MatchStatus.POTENTIAL,
                confidence=0.45,
                cve_id=record.cve_id.upper(),
                package_name=normalize_package_name(package.name),
                installed_version=installed,
                affected_versions=", ".join(matched_ranges),
                fixed_version=_nvd_fixed(record),
                sources=["nvd"],
                evidence=[
                    Evidence(
                        source="nvd",
                        advisory_id=record.cve_id,
                        detail=detail,
                        illustrative=record.illustrative,
                    )
                ],
                cvss=record.cvss,
                severity=record.severity,
                version_style="deb",
            )
        )
    return results


def _from_trivy(hit: TrivyHit, known: set[tuple[str, str]]) -> CorrelationResult | None:
    if not hit.cve_id:
        return None
    name = normalize_package_name(hit.package_name)
    matched = (name, hit.installed_version) in known
    status = trivy_status(hit) if matched else MatchStatus.POTENTIAL
    if not matched and hit.status.lower() in {"not_affected"}:
        return None
    confidence = 0.85 if matched and status == MatchStatus.CONFIRMED else 0.4
    evidence = trivy_evidence(hit)
    if not matched:
        evidence.detail += " The package version was not present in the collected inventory."
    return CorrelationResult(
        status=status,
        confidence=confidence,
        cve_id=hit.cve_id,
        package_name=name,
        installed_version=hit.installed_version,
        affected_versions=hit.status or "trivy match",
        fixed_version=hit.fixed_version,
        sources=["trivy"],
        evidence=[evidence],
        cvss=hit.cvss,
        severity=hit.severity,
    )


def _from_inspector(hit: InspectorHit, known: set[tuple[str, str]]) -> CorrelationResult | None:
    if hit.status.upper() == "CLOSED":
        return None
    name = normalize_package_name(hit.package_name)
    matched = (name, hit.installed_version) in known
    status = MatchStatus.CONFIRMED if matched else MatchStatus.POTENTIAL
    return CorrelationResult(
        status=status,
        confidence=0.8 if matched else 0.4,
        cve_id=hit.cve_id,
        package_name=name,
        installed_version=hit.installed_version,
        affected_versions="Amazon Inspector package finding",
        fixed_version=hit.fixed_version,
        sources=["inspector"],
        evidence=[
            Evidence(
                source="inspector",
                advisory_id=hit.finding_arn,
                detail=(
                    f"Inspector {hit.status or 'ACTIVE'} finding {hit.cve_id} on {hit.package_name} "
                    f"{hit.installed_version}, fixed {hit.fixed_version or 'unknown'}."
                ),
            )
        ],
        severity=hit.severity,
    )


def _merge(items: list[CorrelationResult]) -> CorrelationResult:
    authoritative = [item for item in items if _AUTHORITATIVE.intersection(item.sources)]
    auth_decisions = {
        item.status
        for item in authoritative
        if item.status in {MatchStatus.CONFIRMED, MatchStatus.NOT_AFFECTED}
    }
    if len(auth_decisions) > 1:
        status = MatchStatus.POTENTIAL
        confidence = 0.4
    elif MatchStatus.NOT_AFFECTED in auth_decisions:
        status = MatchStatus.NOT_AFFECTED
        confidence = 0.9
    elif MatchStatus.CONFIRMED in auth_decisions:
        status = MatchStatus.CONFIRMED
        confidence = 0.9
    elif any(item.status == MatchStatus.CONFIRMED and ({"trivy", "inspector"} & set(item.sources)) for item in items):
        status = MatchStatus.CONFIRMED
        confidence = max(item.confidence for item in items if item.status == MatchStatus.CONFIRMED)
    elif any(item.status == MatchStatus.POTENTIAL for item in items):
        status = MatchStatus.POTENTIAL
        confidence = max(item.confidence for item in items if item.status == MatchStatus.POTENTIAL)
    else:
        status = items[0].status
        confidence = items[0].confidence
    decision_statuses = {item.status for item in items if item.status != MatchStatus.UNKNOWN}
    disagree = MatchStatus.NOT_AFFECTED in decision_statuses and (
        MatchStatus.CONFIRMED in decision_statuses or MatchStatus.POTENTIAL in decision_statuses
    )
    if disagree and status == MatchStatus.NOT_AFFECTED:
        confidence = min(confidence, 0.8)
    evidence: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    sources: list[str] = []
    cvss_values = [item.cvss for item in items if item.cvss is not None]
    fixed = next((item.fixed_version for item in authoritative if item.fixed_version), None)
    if fixed is None:
        fixed = next((item.fixed_version for item in items if item.fixed_version), None)
    ranges = []
    for item in items:
        for source in item.sources:
            if source not in sources:
                sources.append(source)
        if item.affected_versions and item.affected_versions not in ranges:
            ranges.append(item.affected_versions)
        for entry in item.evidence:
            key = (entry.source, entry.detail)
            if key not in seen:
                seen.add(key)
                evidence.append(entry)
    if disagree:
        evidence.append(
            Evidence(
                source="correlator",
                detail=(
                    "Sources disagreed. An exact vendor or OSV version comparison takes precedence "
                    "over NVD upstream ranges and scanner output. Both sides are retained."
                ),
            )
        )
    base = items[0]
    score = max(cvss_values) if cvss_values else None
    return CorrelationResult(
        status=status,
        confidence=confidence,
        cve_id=base.cve_id,
        package_name=base.package_name,
        installed_version=_preferred_version(items),
        affected_versions="; ".join(ranges),
        fixed_version=fixed,
        sources=sources,
        evidence=evidence,
        cvss=score,
        severity=_severity(score) or next((item.severity for item in items if item.severity), None),
        version_style=next((item.version_style for item in authoritative if item.version_style), base.version_style),
    )


def enrich_kev(result: CorrelationResult, intel: IntelBundle) -> CorrelationResult:
    record = intel.kev.get(result.cve_id.upper())
    if record is None:
        return result
    detail = (
        f"CISA KEV lists {record.cve_id} ({record.name or record.product}) "
        f"added {record.date_added or 'unknown'}, ransomware use {record.ransomware_use or 'unknown'}. "
        "CloudRecon does not retrieve exploit code."
    )
    if record.snapshot_note:
        detail += f" Snapshot note: {record.snapshot_note}"
    result.kev = True
    result.kev_detail = record.model_dump()
    if "cisa-kev" not in result.sources:
        result.sources.append("cisa-kev")
    result.evidence.append(Evidence(source="cisa-kev", advisory_id=record.cve_id, detail=detail))
    return result


def _applies(advisory: Advisory, host_ecosystem: str, manager: str) -> bool:
    family = advisory.ecosystem.split(":", 1)[0].lower()
    if family in _APP_ECOSYSTEMS:
        return style_for_manager(manager) == "pep440"
    return advisory.ecosystem == host_ecosystem


def _preferred_version(items: list[CorrelationResult]) -> str:
    for item in items:
        if _AUTHORITATIVE.intersection(item.sources):
            return item.installed_version
    return items[0].installed_version


def _nvd_fixed(record: object) -> str | None:
    for match in record.cpe_matches:
        if match.version_end_excluding:
            return match.version_end_excluding
        if match.version_end_including:
            return match.version_end_including
    return None


def _severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
