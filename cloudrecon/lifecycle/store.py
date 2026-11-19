"""SQLite persistence for assets, scans, inventory, and finding lifecycle."""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from cloudrecon.errors import CloudReconError
from cloudrecon.models import (
    MANUAL_REMEDIATION,
    OPEN_REMEDIATION,
    Asset,
    ExposureAssessment,
    FindingRecord,
    HostInventory,
    PrioritizedFinding,
    RemediationStatus,
    ScanRecord,
)
from cloudrecon.util import dump_json, isoformat, load_json, project_root, utcnow

_FINDING_SORTS = {
    "priority_score": "f.priority_score",
    "cvss": "f.cvss",
    "last_seen": "f.last_seen",
    "cve_id": "f.cve_id",
}


def fingerprint(asset_id: str, cve_id: str, package_name: str, installed_version: str) -> str:
    raw = "|".join([asset_id, cve_id.upper(), package_name.lower(), installed_version])
    return hashlib.sha256(raw.encode()).hexdigest()


class Repository:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            schema = (project_root() / "database" / "schema.sql").read_text(encoding="utf-8")
            conn.executescript(schema)
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES ('version', '1')"
            )

    def _connect(self) -> _Closing:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return _Closing(conn)

    def upsert_asset(self, asset: Asset, seen_at: str | None = None) -> None:
        moment = seen_at or isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO assets (
                    asset_id, account_id, region, instance_id, name, instance_type, state,
                    private_ip, public_ip, ami_id, vpc_id, subnet_id, iam_profile,
                    ssm_managed, ssm_ping_status, launch_time, environment, criticality,
                    security_groups_json, tags_json, has_igw_route, load_balancers_json,
                    sg_collected, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    name=excluded.name, instance_type=excluded.instance_type, state=excluded.state,
                    private_ip=excluded.private_ip, public_ip=excluded.public_ip, ami_id=excluded.ami_id,
                    vpc_id=excluded.vpc_id, subnet_id=excluded.subnet_id, iam_profile=excluded.iam_profile,
                    ssm_managed=excluded.ssm_managed, ssm_ping_status=excluded.ssm_ping_status,
                    launch_time=excluded.launch_time, environment=excluded.environment,
                    criticality=excluded.criticality, security_groups_json=excluded.security_groups_json,
                    tags_json=excluded.tags_json, has_igw_route=excluded.has_igw_route,
                    load_balancers_json=excluded.load_balancers_json, sg_collected=excluded.sg_collected,
                    last_seen=excluded.last_seen
                """,
                (
                    asset.asset_id, asset.account_id, asset.region, asset.instance_id, asset.name,
                    asset.instance_type, asset.state, asset.private_ip, asset.public_ip, asset.ami_id,
                    asset.vpc_id, asset.subnet_id, asset.iam_profile, _bit(asset.ssm_managed),
                    asset.ssm_ping_status, asset.launch_time, asset.environment, asset.criticality,
                    dump_json([item.model_dump() for item in asset.security_groups]),
                    dump_json(asset.tags), _bit(asset.has_igw_route),
                    dump_json([item.model_dump() for item in asset.load_balancers]),
                    1 if asset.sg_collected else 0, moment, moment,
                ),
            )

    def mark_missing(self, seen_ids: set[str], *, full: bool) -> int:
        if not full:
            return 0
        with self._connect() as conn:
            rows = conn.execute("SELECT asset_id, state FROM assets").fetchall()
            changed = 0
            for row in rows:
                if row["asset_id"] in seen_ids or row["state"] == "missing":
                    continue
                conn.execute("UPDATE assets SET state = 'missing' WHERE asset_id = ?", (row["asset_id"],))
                changed += 1
            return changed

    def start_scan(self, mode: str, scope: str, *, demo: bool, started_at: str | None = None) -> str:
        scan_id = uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (id, mode, status, started_at, scope, stats_json, demo)
                VALUES (?, ?, 'running', ?, ?, '{}', ?)
                """,
                (scan_id, mode, started_at or isoformat(), scope, 1 if demo else 0),
            )
        return scan_id

    def finish_scan(
        self,
        scan_id: str,
        status: str,
        stats: dict[str, Any],
        error: str | None = None,
        finished_at: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE scans SET status = ?, finished_at = ?, stats_json = ?, error = ?
                WHERE id = ?
                """,
                (status, finished_at or isoformat(), dump_json(stats), error, scan_id),
            )

    def add_error(
        self,
        scan_id: str,
        asset_id: str | None,
        stage: str,
        message: str,
        created_at: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_errors (scan_id, asset_id, stage, message, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, asset_id, stage, message[:2000], created_at or isoformat()),
            )

    def save_snapshot(self, scan_id: str, asset_id: str, host: HostInventory) -> str:
        snapshot_id = uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO snapshots (
                    id, scan_id, asset_id, collected_at, collection_status, packages_complete,
                    os_json, errors_json, docker_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id, scan_id, asset_id, host.collected_at or isoformat(),
                    host.collection_status, 1 if host.packages_complete else 0,
                    dump_json(host.os), dump_json(host.errors), host.docker_status,
                ),
            )
            conn.executemany(
                """
                INSERT INTO packages (snapshot_id, name, version, release, epoch, arch, manager, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (snapshot_id, pkg.name, pkg.version, pkg.release, pkg.epoch, pkg.arch, pkg.manager, pkg.source)
                    for pkg in host.packages
                ],
            )
            conn.executemany(
                """
                INSERT INTO services (snapshot_id, name, port, protocol, process, pid, executable, address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (snapshot_id, svc.name, svc.port, svc.protocol, svc.process, svc.pid, svc.executable, svc.address)
                    for svc in host.services
                ],
            )
        return snapshot_id

    def save_exposure(self, scan_id: str, exposure: ExposureAssessment, assessed_at: str | None = None) -> None:
        detail = {
            "reasons": exposure.reasons,
            "world_ports": exposure.world_ports,
            "service_notes": exposure.service_notes,
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO exposure (
                    asset_id, scan_id, internet_potential, verified_reachable, sg_open_to_world,
                    summary, detail_json, assessed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    scan_id=excluded.scan_id, internet_potential=excluded.internet_potential,
                    verified_reachable=excluded.verified_reachable, sg_open_to_world=excluded.sg_open_to_world,
                    summary=excluded.summary, detail_json=excluded.detail_json, assessed_at=excluded.assessed_at
                """,
                (
                    exposure.asset_id, scan_id, _bit(exposure.internet_potential),
                    1 if exposure.verified_reachable else 0, _bit(exposure.sg_open_to_world),
                    exposure.summary, dump_json(detail), assessed_at or isoformat(),
                ),
            )

    def upsert_finding(self, scan_id: str, item: PrioritizedFinding, *, demo: bool, seen_at: str | None = None) -> str:
        correlation = item.correlation
        digest = fingerprint(
            item.asset_id, correlation.cve_id, correlation.package_name, correlation.installed_version
        )
        moment = seen_at or isoformat()
        illustrative = any(entry.illustrative for entry in correlation.evidence) or correlation.cve_id.startswith(
            "CVE-9999-"
        )
        evidence = [entry.model_dump() for entry in correlation.evidence]
        explanation = [factor.model_dump() for factor in item.priority_factors]
        with self._connect() as conn:
            existing = conn.execute("SELECT * FROM findings WHERE fingerprint = ?", (digest,)).fetchone()
            if existing is None:
                finding_id = uuid.uuid4().hex
                conn.execute(
                    """
                    INSERT INTO findings (
                        id, fingerprint, asset_id, cve_id, package_name, installed_version,
                        affected_versions, fixed_version, advisory_sources, cvss, severity, kev,
                        kev_json, match_status, confidence, evidence_json, priority_band,
                        priority_score, priority_explanation, priority_disclaimer, remediation_status,
                        first_seen, last_seen, last_scan_id, demo, illustrative
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id, digest, item.asset_id, correlation.cve_id.upper(), correlation.package_name,
                        correlation.installed_version, correlation.affected_versions, correlation.fixed_version,
                        dump_json(correlation.sources), correlation.cvss, correlation.severity,
                        1 if correlation.kev else 0, dump_json(correlation.kev_detail), correlation.status.value,
                        correlation.confidence, dump_json(evidence), item.priority_band, item.priority_score,
                        dump_json(explanation), item.priority_disclaimer, moment, moment, scan_id,
                        1 if demo else 0, 1 if illustrative else 0,
                    ),
                )
                self._event(conn, finding_id, scan_id, "opened", "Finding observed", moment)
                return "opened"
            finding_id = existing["id"]
            status = existing["remediation_status"]
            event = "updated"
            resolved_at = existing["resolved_at"]
            if status == RemediationStatus.RESOLVED.value:
                status = RemediationStatus.OPEN.value
                resolved_at = None
                event = "reopened"
            merged_evidence = _merge_evidence(load_json(existing["evidence_json"], []), evidence)
            merged_sources = _union(load_json(existing["advisory_sources"], []), correlation.sources)
            conn.execute(
                """
                UPDATE findings SET
                    affected_versions=?, fixed_version=?, advisory_sources=?, cvss=?, severity=?,
                    kev=?, kev_json=?, match_status=?, confidence=?, evidence_json=?, priority_band=?,
                    priority_score=?, priority_explanation=?, priority_disclaimer=?, remediation_status=?,
                    last_seen=?, resolved_at=?, last_scan_id=?, illustrative=?
                WHERE id=?
                """,
                (
                    correlation.affected_versions, correlation.fixed_version, dump_json(merged_sources),
                    correlation.cvss, correlation.severity, 1 if correlation.kev else 0,
                    dump_json(correlation.kev_detail), correlation.status.value, correlation.confidence,
                    dump_json(merged_evidence), item.priority_band, item.priority_score, dump_json(explanation),
                    item.priority_disclaimer, status, moment, resolved_at, scan_id,
                    1 if illustrative or existing["illustrative"] else 0, finding_id,
                ),
            )
            self._event(conn, finding_id, scan_id, event, "Finding observed again", moment)
            return event

    def resolve_unobserved(
        self,
        scan_id: str,
        asset_id: str,
        active_fingerprints: set[str],
        *,
        collection_ok: bool,
        seen_at: str | None = None,
    ) -> list[str]:
        moment = seen_at or isoformat()
        if not collection_ok:
            self.add_error(
                scan_id,
                asset_id,
                "lifecycle",
                "Resolution skipped because package collection was incomplete or failed.",
                moment,
            )
            return []
        resolved: list[str] = []
        open_states = tuple(status.value for status in OPEN_REMEDIATION)
        placeholders = ",".join("?" for _ in open_states)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings WHERE asset_id = ? AND remediation_status IN ({placeholders})",
                (asset_id, *open_states),
            ).fetchall()
            for row in rows:
                if row["fingerprint"] in active_fingerprints:
                    continue
                conn.execute(
                    """
                    UPDATE findings SET remediation_status = 'resolved', resolved_at = ?, last_scan_id = ?
                    WHERE id = ?
                    """,
                    (moment, scan_id, row["id"]),
                )
                self._event(
                    conn,
                    row["id"],
                    scan_id,
                    "resolved",
                    "Successful rescan did not observe this vulnerable package version.",
                    moment,
                )
                resolved.append(row["id"])
        return resolved

    def set_remediation(self, finding_id: str, status: str, note: str) -> None:
        try:
            parsed = RemediationStatus(status)
        except ValueError as exc:
            raise CloudReconError(f"Unknown remediation status: {status}") from exc
        if parsed == RemediationStatus.RESOLVED:
            raise CloudReconError("Resolved is recorded only after a successful rescan")
        if parsed not in MANUAL_REMEDIATION:
            raise CloudReconError(f"Status {status} cannot be set manually")
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone()
            if row is None:
                raise CloudReconError(f"Finding not found: {finding_id}")
            conn.execute(
                "UPDATE findings SET remediation_status = ?, status_note = ? WHERE id = ?",
                (parsed.value, note[:1000], finding_id),
            )
            self._event(conn, finding_id, None, "status_changed", f"{parsed.value}: {note[:300]}", isoformat())

    def list_assets(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM assets ORDER BY region, name").fetchall()
        return [dict(row) for row in rows]

    def get_asset(self, asset_id: str) -> Asset | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
        if row is None:
            return None
        return _asset_from_row(row)

    def list_findings(self, **filters: Any) -> list[FindingRecord]:
        clauses = ["1=1"]
        params: list[Any] = []
        if filters.get("severity"):
            clauses.append("f.severity = ?")
            params.append(str(filters["severity"]).upper())
        if filters.get("priority_band"):
            clauses.append("f.priority_band = ?")
            params.append(filters["priority_band"])
        if filters.get("remediation_status"):
            clauses.append("f.remediation_status = ?")
            params.append(filters["remediation_status"])
        if filters.get("match_status"):
            clauses.append("f.match_status = ?")
            params.append(filters["match_status"])
        if filters.get("region"):
            clauses.append("a.region = ?")
            params.append(filters["region"])
        if filters.get("kev") is True:
            clauses.append("f.kev = 1")
        if filters.get("asset_id"):
            clauses.append("f.asset_id = ?")
            params.append(filters["asset_id"])
        if filters.get("q"):
            clauses.append(
                "(f.cve_id LIKE ? ESCAPE '\\' OR f.package_name LIKE ? ESCAPE '\\' "
                "OR a.name LIKE ? ESCAPE '\\' OR f.asset_id LIKE ? ESCAPE '\\')"
            )
            like = _like(str(filters["q"])[:200])
            params.extend([like, like, like, like])
        sort = _FINDING_SORTS.get(str(filters.get("sort") or "priority_score"), "f.priority_score")
        direction = "ASC" if str(filters.get("direction") or "desc").lower() == "asc" else "DESC"
        limit = min(max(int(filters.get("limit") or 200), 1), 500)
        offset = max(int(filters.get("offset") or 0), 0)
        sql = f"""
            SELECT f.*, a.region, a.name AS asset_name, a.environment
            FROM findings f JOIN assets a ON a.asset_id = f.asset_id
            WHERE {' AND '.join(clauses)}
            ORDER BY {sort} {direction}, f.cve_id ASC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_finding_from_row(row) for row in rows]

    def list_scans(self) -> list[ScanRecord]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        return [
            ScanRecord(
                id=row["id"], mode=row["mode"], status=row["status"], started_at=row["started_at"],
                finished_at=row["finished_at"], scope=row["scope"] or "", stats=load_json(row["stats_json"], {}),
                error=row["error"], demo=bool(row["demo"]),
            )
            for row in rows
        ]

    def list_exposure(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT e.*, a.region, a.name, a.public_ip, a.instance_id
                FROM exposure e JOIN assets a ON a.asset_id = e.asset_id
                ORDER BY a.region, a.name
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def list_errors(self, scan_id: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT * FROM scan_errors WHERE scan_id = ? ORDER BY id", (scan_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM scan_errors ORDER BY id DESC LIMIT 200").fetchall()
        return [dict(row) for row in rows]

    def metrics(self) -> dict[str, Any]:
        with self._connect() as conn:
            assets = conn.execute("SELECT COUNT(*) AS n FROM assets").fetchone()["n"]
            scanned = conn.execute(
                """
                WITH latest AS (
                    SELECT collection_status, packages_complete,
                           ROW_NUMBER() OVER (
                               PARTITION BY asset_id ORDER BY collected_at DESC, rowid DESC
                           ) AS rn
                    FROM snapshots
                )
                SELECT COUNT(*) AS n FROM latest
                WHERE rn = 1 AND collection_status = 'success' AND packages_complete = 1
                """
            ).fetchone()["n"]
            open_clause = "remediation_status IN ('open', 'under_investigation', 'remediation_in_progress')"
            by_severity = {
                row["severity"] or "UNKNOWN": row["n"]
                for row in conn.execute(
                    f"SELECT severity, COUNT(*) AS n FROM findings WHERE {open_clause} GROUP BY severity"
                )
            }
            by_band = {
                row["priority_band"] or "unscored": row["n"]
                for row in conn.execute(
                    f"SELECT priority_band, COUNT(*) AS n FROM findings WHERE {open_clause} GROUP BY priority_band"
                )
            }
            by_region = {
                row["region"]: row["n"]
                for row in conn.execute(
                    f"""
                    SELECT a.region AS region, COUNT(*) AS n
                    FROM findings f JOIN assets a ON a.asset_id = f.asset_id
                    WHERE f.{open_clause}
                    GROUP BY a.region
                    """
                )
            }
            kev = conn.execute(
                f"SELECT COUNT(*) AS n FROM findings WHERE kev = 1 AND {open_clause}"
            ).fetchone()["n"]
            exposed = conn.execute(
                "SELECT COUNT(*) AS n FROM exposure WHERE internet_potential = 1"
            ).fetchone()["n"]
            unknown_exposure = conn.execute(
                "SELECT COUNT(*) AS n FROM exposure WHERE internet_potential IS NULL"
            ).fetchone()["n"]
            top = conn.execute(
                f"""
                SELECT a.name, f.asset_id, COUNT(*) AS findings, ROUND(SUM(f.priority_score), 2) AS score
                FROM findings f JOIN assets a ON a.asset_id = f.asset_id
                WHERE f.{open_clause}
                GROUP BY f.asset_id
                ORDER BY score DESC
                LIMIT 5
                """
            ).fetchall()
            trend = conn.execute(
                """
                SELECT substr(created_at, 1, 10) AS day, event_type, COUNT(*) AS n
                FROM finding_events
                WHERE event_type IN ('opened', 'resolved', 'reopened')
                GROUP BY day, event_type
                ORDER BY day
                """
            ).fetchall()
            remediation = {
                row["remediation_status"]: row["n"]
                for row in conn.execute(
                    "SELECT remediation_status, COUNT(*) AS n FROM findings GROUP BY remediation_status"
                )
            }
        return {
            "assets": assets,
            "scanned_assets": scanned,
            "unscanned_assets": assets - scanned,
            "open_by_severity": by_severity,
            "open_by_priority": by_band,
            "open_by_region": by_region,
            "open_kev": kev,
            "potential_internet_exposed": exposed,
            "unknown_exposure": unknown_exposure,
            "most_vulnerable_assets": [dict(row) for row in top],
            "trend": [dict(row) for row in trend],
            "remediation": remediation,
            "generated_at": isoformat(utcnow()),
        }

    def _event(
        self,
        conn: sqlite3.Connection,
        finding_id: str,
        scan_id: str | None,
        event_type: str,
        detail: str,
        created_at: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO finding_events (finding_id, scan_id, event_type, detail, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (finding_id, scan_id, event_type, detail, created_at),
        )


class _Closing:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self.conn

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            if exc_type:
                self.conn.rollback()
            else:
                self.conn.commit()
        finally:
            self.conn.close()


def _bit(value: bool | None) -> int | None:
    if value is None:
        return None
    return 1 if value else 0


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _union(existing: list[str], extra: list[str]) -> list[str]:
    merged = list(existing)
    for item in extra:
        if item not in merged:
            merged.append(item)
    return merged


def _merge_evidence(existing: list[dict[str, Any]], extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = list(existing)
    seen = {(item.get("source"), item.get("detail")) for item in existing}
    for item in extra:
        key = (item.get("source"), item.get("detail"))
        if key not in seen:
            merged.append(item)
            seen.add(key)
    return merged


def _finding_from_row(row: sqlite3.Row) -> FindingRecord:
    return FindingRecord(
        id=row["id"], fingerprint=row["fingerprint"], asset_id=row["asset_id"], cve_id=row["cve_id"],
        package_name=row["package_name"], installed_version=row["installed_version"],
        affected_versions=row["affected_versions"] or "", fixed_version=row["fixed_version"],
        advisory_sources=load_json(row["advisory_sources"], []), cvss=row["cvss"], severity=row["severity"],
        kev=bool(row["kev"]), kev_detail=load_json(row["kev_json"], {}), match_status=row["match_status"],
        confidence=row["confidence"], evidence=load_json(row["evidence_json"], []),
        priority_band=row["priority_band"], priority_score=row["priority_score"],
        priority_explanation=load_json(row["priority_explanation"], []),
        priority_disclaimer=row["priority_disclaimer"] or "", remediation_status=row["remediation_status"],
        first_seen=row["first_seen"], last_seen=row["last_seen"], resolved_at=row["resolved_at"],
        last_scan_id=row["last_scan_id"], status_note=row["status_note"] or "", demo=bool(row["demo"]),
        illustrative=bool(row["illustrative"]), region=row["region"] if "region" in row.keys() else "",
        asset_name=row["asset_name"] if "asset_name" in row.keys() else "",
        environment=row["environment"] if "environment" in row.keys() else "",
    )


def _asset_from_row(row: sqlite3.Row) -> Asset:
    from cloudrecon.models import LoadBalancerRef, SecurityGroup

    return Asset(
        asset_id=row["asset_id"], account_id=row["account_id"], region=row["region"],
        instance_id=row["instance_id"], name=row["name"] or "", instance_type=row["instance_type"] or "",
        state=row["state"] or "", private_ip=row["private_ip"], public_ip=row["public_ip"],
        ami_id=row["ami_id"] or "", vpc_id=row["vpc_id"] or "", subnet_id=row["subnet_id"] or "",
        iam_profile=row["iam_profile"] or "", ssm_managed=_tribool(row["ssm_managed"]),
        ssm_ping_status=row["ssm_ping_status"] or "", launch_time=row["launch_time"] or "",
        environment=row["environment"] or "", criticality=row["criticality"] or "",
        security_groups=[SecurityGroup.model_validate(item) for item in load_json(row["security_groups_json"], [])],
        tags=load_json(row["tags_json"], {}), has_igw_route=_tribool(row["has_igw_route"]),
        load_balancers=[LoadBalancerRef.model_validate(item) for item in load_json(row["load_balancers_json"], [])],
        sg_collected=bool(row["sg_collected"]),
    )


def _tribool(value: int | None) -> bool | None:
    if value is None:
        return None
    return bool(value)
