"""Assessment orchestration. Collectors, correlation, exposure, and storage stay separate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from cloudrecon.config import Settings
from cloudrecon.exposure.analyzer import analyze_exposure
from cloudrecon.intel.correlator import correlate
from cloudrecon.intel.feeds import IntelBundle, load_intel_files
from cloudrecon.intel.inspector import InspectorHit
from cloudrecon.intel.trivy import TrivyHit
from cloudrecon.lifecycle.store import Repository, fingerprint
from cloudrecon.logging_utils import get_logger
from cloudrecon.models import Asset, HostInventory, MatchStatus
from cloudrecon.risk.engine import load_rules, prioritize
from cloudrecon.util import isoformat

LOGGER = get_logger(__name__)


@dataclass
class ScanStats:
    assets: int = 0
    hosts_collected: int = 0
    hosts_failed: int = 0
    hosts_skipped: int = 0
    findings_opened: int = 0
    findings_updated: int = 0
    findings_reopened: int = 0
    findings_resolved: int = 0
    out_of_scope: int = 0
    errors: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "assets": self.assets,
            "hosts_collected": self.hosts_collected,
            "hosts_failed": self.hosts_failed,
            "hosts_skipped": self.hosts_skipped,
            "findings_opened": self.findings_opened,
            "findings_updated": self.findings_updated,
            "findings_reopened": self.findings_reopened,
            "findings_resolved": self.findings_resolved,
            "out_of_scope": self.out_of_scope,
            "errors": self.errors,
        }


@dataclass
class AssessmentSource:
    mode: str
    assets: list[Asset]
    hosts: dict[str, HostInventory | None]
    errors: list[str] = field(default_factory=list)
    trivy: dict[str, list[TrivyHit]] = field(default_factory=dict)
    inspector: dict[str, list[InspectorHit]] = field(default_factory=dict)


class Alerter(Protocol):
    def scan_failed(self, scan_id: str, error: str) -> None: ...

    def findings_opened(self, findings: list[dict[str, str]]) -> None: ...


class NullAlerter:
    def scan_failed(self, scan_id: str, error: str) -> None:
        return None

    def findings_opened(self, findings: list[dict[str, str]]) -> None:
        return None


def load_offline_intel(settings: Settings) -> IntelBundle:
    return load_intel_files(
        settings.path_for(settings.advisory_path),
        settings.path_for(settings.nvd_snapshot_path),
        settings.path_for(settings.kev_path),
    )


def run_assessment(
    settings: Settings,
    source: AssessmentSource,
    *,
    now: datetime | None = None,
    demo: bool = False,
    full_reconcile: bool = False,
    alerter: Alerter | None = None,
    intel: IntelBundle | None = None,
) -> tuple[str, ScanStats]:
    notifier = alerter or NullAlerter()
    repo = Repository(settings.database)
    rules = load_rules(settings.path_for(settings.risk_rules_path))
    bundle = intel or load_offline_intel(settings)
    moment = isoformat(now)
    scan_id = repo.start_scan(source.mode, scope=f"assets={len(source.assets)}", demo=demo, started_at=moment)
    stats = ScanStats(assets=len(source.assets))
    opened_alerts: list[dict[str, str]] = []
    try:
        for message in source.errors:
            repo.add_error(scan_id, None, "discovery", message, moment)
            stats.errors += 1
        seen: set[str] = set()
        for asset in source.assets:
            seen.add(asset.asset_id)
            repo.upsert_asset(asset, moment)
            host = source.hosts.get(asset.asset_id)
            exposure = analyze_exposure(asset, host)
            repo.save_exposure(scan_id, exposure, moment)
            if host is None:
                stats.hosts_skipped += 1
                repo.add_error(scan_id, asset.asset_id, "host", "No host inventory was collected.", moment)
                continue
            repo.save_snapshot(scan_id, asset.asset_id, host)
            collection_ok = host.collection_status == "success" and host.packages_complete
            if collection_ok:
                stats.hosts_collected += 1
            else:
                stats.hosts_failed += 1
                repo.add_error(
                    scan_id,
                    asset.asset_id,
                    "host",
                    "Host collection did not complete successfully: " + "; ".join(host.errors[:5]),
                    moment,
                )
            matches = correlate(
                host,
                bundle,
                trivy_hits=source.trivy.get(asset.asset_id),
                inspector_hits=source.inspector.get(asset.asset_id),
            )
            active: set[str] = set()
            for match in matches:
                if match.status not in {MatchStatus.CONFIRMED, MatchStatus.POTENTIAL}:
                    continue
                prioritized = prioritize(match, asset, exposure, rules)
                event = repo.upsert_finding(scan_id, prioritized, demo=demo, seen_at=moment)
                digest = fingerprint(
                    asset.asset_id, match.cve_id, match.package_name, match.installed_version
                )
                active.add(digest)
                if event == "opened":
                    stats.findings_opened += 1
                    if prioritized.priority_band in {"critical", "high"}:
                        opened_alerts.append(
                            {
                                "asset_id": asset.asset_id,
                                "cve_id": match.cve_id,
                                "priority": prioritized.priority_band,
                                "package": match.package_name,
                            }
                        )
                elif event == "reopened":
                    stats.findings_reopened += 1
                else:
                    stats.findings_updated += 1
            resolved = repo.resolve_unobserved(
                scan_id, asset.asset_id, active, collection_ok=collection_ok, seen_at=moment
            )
            stats.findings_resolved += len(resolved)
        stats.out_of_scope += repo.mark_missing(seen, full=full_reconcile)
        repo.finish_scan(scan_id, "completed", stats.as_dict(), finished_at=moment)
        if opened_alerts:
            notifier.findings_opened(opened_alerts)
        return scan_id, stats
    except Exception as exc:
        LOGGER.exception("assessment failed")
        repo.finish_scan(scan_id, "failed", stats.as_dict(), error=str(exc), finished_at=moment)
        notifier.scan_failed(scan_id, str(exc))
        raise
