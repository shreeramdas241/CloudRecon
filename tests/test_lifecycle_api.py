from api.main import create_app
from cloudrecon.demo.runner import run_demo
from cloudrecon.errors import CloudReconError
from cloudrecon.lifecycle.store import Repository
from fastapi.testclient import TestClient


def test_demo_lifecycle_dedup_and_resolution(settings) -> None:
    scan_id, stats = run_demo(settings)
    assert stats.findings_resolved == 1
    assert stats.hosts_failed == 1
    assert stats.hosts_skipped == 1
    repo = Repository(settings.database)
    findings = repo.list_findings(limit=50)
    by_key = {(item.asset_name, item.cve_id, item.remediation_status) for item in findings}
    assert ("demo-web-1", "CVE-9999-0001", "open") in by_key
    assert ("demo-web-1", "CVE-9999-0002", "resolved") in by_key
    assert ("demo-app-1", "CVE-2021-44228", "open") in by_key
    assert ("demo-dev-1", "CVE-9999-0003", "open") in by_key
    assert ("demo-partial-1", "CVE-9999-0002", "open") in by_key
    assert ("demo-staging-1", "CVE-9999-0004", "open") in by_key
    assert not any(item.asset_name == "demo-staging-1" and item.cve_id == "CVE-9999-0001" for item in findings)
    curl = next(item for item in findings if item.asset_name == "demo-web-1" and item.cve_id == "CVE-9999-0002")
    assert curl.resolved_at
    partial = next(item for item in findings if item.asset_name == "demo-partial-1")
    assert partial.remediation_status == "open"
    errors = repo.list_errors()
    assert any("Resolution skipped" in error["message"] for error in errors)
    metrics = repo.metrics()
    assert metrics["assets"] == 6
    assert metrics["scanned_assets"] == 4
    assert metrics["unscanned_assets"] == 2
    assert metrics["open_kev"] == 1
    assert metrics["potential_internet_exposed"] == 3
    before = repo.list_findings(limit=50, remediation_status="open", q="CVE-2021-44228")
    evidence_before = len(before[0].evidence)
    _scan_id, second = run_demo(settings)
    assert second.findings_opened == 0
    refreshed = repo.list_findings(limit=50, q="CVE-2021-44228")
    assert len(refreshed) == 1
    assert len(refreshed[0].evidence) == evidence_before
    try:
        repo.set_remediation(refreshed[0].id, "resolved", "manual")
    except CloudReconError as exc:
        assert "rescan" in str(exc)
    else:
        raise AssertionError("manual resolve must fail")
    repo.set_remediation(refreshed[0].id, "under_investigation", "owner assigned")
    updated = repo.list_findings(q="CVE-2021-44228", limit=10)[0]
    assert updated.remediation_status == "under_investigation"
    assert scan_id


def test_mark_missing_requires_full_reconcile(settings) -> None:
    run_demo(settings)
    repo = Repository(settings.database)
    assert repo.mark_missing(set(), full=False) == 0
    changed = repo.mark_missing(set(), full=True)
    assert changed == 6
    assert all(row["state"] == "missing" for row in repo.list_assets())


def test_api_validation_and_exports(settings) -> None:
    run_demo(settings)
    client = TestClient(create_app(settings))
    assert client.get("/health").json()["mode"] == "demo"
    assert client.get("/api/v1/metrics").json()["assets"] == 6
    denied = client.patch("/api/v1/findings/missing", json={"status": "resolved", "note": "no"})
    assert denied.status_code == 400
    bad_limit = client.get("/api/v1/findings", params={"limit": 0})
    assert bad_limit.status_code == 422
    exported = client.get("/api/v1/findings/export", params={"fmt": "csv"})
    assert exported.status_code == 200
    assert "CVE-2021-44228" in exported.text
    report = client.get("/api/v1/reports/latest")
    assert report.status_code == 200
    assert "Synthetic demonstration" in report.text
    assert "Potentially internet exposed" in report.text
    live_settings = settings.model_copy(update={"mode": "live"})
    live = TestClient(create_app(live_settings))
    assert live.post("/api/v1/scans/demo").status_code == 403
