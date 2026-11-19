import httpx
import pytest
from cloudrecon.automation.notify import NotificationService
from cloudrecon.automation.scheduler import ScanScheduler
from cloudrecon.config import Settings
from cloudrecon.demo.fixtures import demo_assets, hosts_after
from cloudrecon.errors import ScopeError
from cloudrecon.intel.clients import NvdClient
from cloudrecon.intel.feeds import load_kev_document, parse_nvd_api, parse_osv_vuln
from cloudrecon.intel.http import ResponseCache
from cloudrecon.lifecycle.store import Repository
from cloudrecon.pipeline import AssessmentSource, run_assessment
from cloudrecon.scope import load_scope
from cloudrecon.security import redact
from cloudrecon.util import project_root


def test_redaction_hides_keys_and_access_key_ids() -> None:
    cleaned = redact({"aws_secret_access_key": "super-secret", "note": "key AKIAIOSFODNN7EXAMPLE"})
    assert cleaned["aws_secret_access_key"] == "***"
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned["note"]
    assert "super-secret" not in str(cleaned)


def test_scope_file_and_empty_scope(tmp_path) -> None:
    scope = load_scope(project_root() / "config" / "scope.example.yaml")
    assert scope.accounts == ["111122223333"]
    empty = tmp_path / "scope.yaml"
    empty.write_text("accounts: []\nregions: []\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(empty)


def test_scheduler_backs_off_without_sleeping_the_suite() -> None:
    calls = {"n": 0}
    sleeps: list[float] = []

    def runner() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("temporary")

    completed = ScanScheduler(
        runner, interval_seconds=50, backoff_seconds=2, sleeper=sleeps.append
    ).run(max_iterations=2)
    assert completed == 2
    assert sleeps == [2]


def test_nvd_retries_then_caches() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2021-44228",
                            "descriptions": [{"lang": "en", "value": "Log4j"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                                ]
                            },
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {
                                                    "vulnerable": True,
                                                    "criteria": "cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*",
                                                    "versionStartIncluding": "2.0",
                                                    "versionEndExcluding": "2.15.0",
                                                }
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    cache = ResponseCache()
    nvd = NvdClient(client, cache=cache, api_key="test-key", sleeper=lambda _seconds: None)
    record = nvd.get_cve("CVE-2021-44228")
    assert record is not None
    assert record.cvss == 10.0
    assert record.cpe_matches[0].product == "log4j-core"
    again = nvd.get_cve("CVE-2021-44228")
    assert again is not None
    assert calls["n"] == 2
    parsed = parse_osv_vuln(
        {
            "id": "GHSA-demo",
            "aliases": ["CVE-2021-44228"],
            "summary": "log4j",
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}],
                }
            ],
        }
    )
    assert parsed[0].cve_ids == ["CVE-2021-44228"]
    kev = load_kev_document({"vulnerabilities": [{"cveID": "CVE-2021-44228", "vendorProject": "Apache"}]})
    assert "CVE-2021-44228" in kev
    assert parse_nvd_api({"vulnerabilities": []}) == []


def test_failed_correlation_marks_the_scan_failed(settings: Settings) -> None:
    def boom(*_args, **_kwargs):
        raise RuntimeError("intel down")

    import cloudrecon.pipeline as pipeline

    pipeline.correlate = boom
    try:
        run_assessment(
            settings,
            AssessmentSource(
                mode="demo",
                assets=demo_assets(),
                hosts=hosts_after("2026-01-01T00:00:00+00:00"),
                errors=["region denied"],
            ),
            demo=True,
        )
    except RuntimeError as exc:
        assert "intel down" in str(exc)
    finally:
        import importlib

        importlib.reload(pipeline)
    scans = Repository(settings.database).list_scans()
    assert scans[0].status == "failed"
    assert any(row["message"] == "region denied" for row in Repository(settings.database).list_errors())


def test_jira_and_webhook_are_optional(settings: Settings) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("/issue"):
            return httpx.Response(201, json={"key": "SEC-1"})
        return httpx.Response(204)

    configured = settings.model_copy(
        update={
            "enable_jira": True,
            "jira_base_url": "https://jira.example",
            "jira_email": "analyst@example.com",
            "jira_api_token": "token-value",
            "jira_project": "SEC",
            "webhook_url": "https://hooks.example/cloudrecon",
        }
    )
    service = NotificationService(configured, httpx.Client(transport=httpx.MockTransport(handler)))
    service.findings_opened([{"cve_id": "CVE-9999-0001", "asset_id": "asset", "package": "curl", "priority": "high"}])
    assert any(path.endswith("/rest/api/3/issue") for path in calls)
    disabled = NotificationService(settings, httpx.Client(transport=httpx.MockTransport(handler)))
    assert disabled.create_jira_issue({"cve_id": "CVE-9999-0001"}) is None
