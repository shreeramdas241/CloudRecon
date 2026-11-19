
import json

from cloudrecon.demo.fixtures import demo_assets, hosts_after
from cloudrecon.intel.correlator import correlate
from cloudrecon.intel.feeds import load_intel_files
from cloudrecon.intel.inspector import parse_inspector_findings
from cloudrecon.intel.trivy import parse_trivy
from cloudrecon.models import HostInventory, MatchStatus, PackageRecord
from cloudrecon.util import project_root


def intel():
    root = project_root() / "examples" / "intel"
    return load_intel_files(root / "vendor_advisories.json", root / "nvd_snapshot.json", root / "kev_snapshot.json")


def _host(packages: list[PackageRecord], os_id: str = "ubuntu", version: str = "22.04") -> HostInventory:
    return HostInventory(
        collected_at="2026-01-01T00:00:00+00:00",
        collection_status="success",
        packages_complete=True,
        os={"id": os_id, "version_id": version},
        packages=packages,
    )


def test_vendor_backport_overrides_nvd() -> None:
    host = _host([PackageRecord(name="libssl3", version="3.0.2-0ubuntu1.18", manager="deb")])
    results = {item.cve_id: item for item in correlate(host, intel())}
    match = results["CVE-9999-0001"]
    assert match.status == MatchStatus.NOT_AFFECTED
    assert match.confidence == 0.8
    sources = {entry.source for entry in match.evidence}
    assert "vendor" in sources
    assert "nvd" in sources
    assert any("precedence" in entry.detail for entry in match.evidence)


def test_vulnerable_revision_is_confirmed() -> None:
    host = _host([PackageRecord(name="libssl3", version="3.0.2-0ubuntu1.10", manager="deb")])
    match = next(item for item in correlate(host, intel()) if item.cve_id == "CVE-9999-0001")
    assert match.status == MatchStatus.CONFIRMED
    assert match.fixed_version == "3.0.2-0ubuntu1.15"
    assert any(entry.illustrative for entry in match.evidence)


def test_log4j_kev_and_nvd_only_nginx() -> None:
    host = _host(
        [
            PackageRecord(name="log4j-core", version="2.14.1", manager="application"),
            PackageRecord(name="nginx", version="1.18.0-1ubuntu1", manager="deb"),
        ]
    )
    results = {item.cve_id: item for item in correlate(host, intel())}
    assert results["CVE-2021-44228"].status == MatchStatus.CONFIRMED
    assert results["CVE-2021-44228"].kev is True
    assert results["CVE-2021-44228"].cvss == 10.0
    assert results["CVE-9999-0004"].status == MatchStatus.POTENTIAL
    assert results["CVE-9999-0004"].confidence == 0.45


def test_different_ubuntu_release_is_not_confirmed() -> None:
    host = _host(
        [PackageRecord(name="libssl3", version="3.0.2-0ubuntu1.10", manager="deb")],
        version="20.04",
    )
    cves = {item.cve_id for item in correlate(host, intel()) if item.status == MatchStatus.CONFIRMED}
    assert "CVE-9999-0001" not in cves


def test_trivy_and_inspector_parsers() -> None:
    trivy = parse_trivy(json.loads((project_root() / "examples" / "sample_trivy.json").read_text(encoding="utf-8")))
    assert trivy[0].cve_id == "CVE-9999-0002"
    raw = json.loads((project_root() / "examples" / "sample_inspector.json").read_text(encoding="utf-8"))
    hits = parse_inspector_findings(raw["findings"])
    assert hits[0].instance_id == "i-0aaa000000000003"
    host = _host([PackageRecord(name="curl", version="7.81.0-1ubuntu1.14", manager="deb")])
    matched = correlate(host, intel(), trivy_hits=trivy)
    curl = next(item for item in matched if item.cve_id == "CVE-9999-0002")
    assert curl.status == MatchStatus.CONFIRMED
    assert "trivy" in curl.sources
    assert "vendor" in curl.sources


def test_demo_hosts_cover_expected_statuses() -> None:
    bundle = intel()
    assets = {asset.name: asset.asset_id for asset in demo_assets()}
    hosts = hosts_after("2026-01-15T00:00:00+00:00")
    web = {item.cve_id: item.status for item in correlate(hosts[assets["demo-web-1"]], bundle)}
    assert web["CVE-9999-0001"] == MatchStatus.CONFIRMED
    assert web["CVE-9999-0002"] == MatchStatus.NOT_AFFECTED
    staging = {item.cve_id: item.status for item in correlate(hosts[assets["demo-staging-1"]], bundle)}
    assert staging["CVE-9999-0001"] == MatchStatus.NOT_AFFECTED
    assert staging["CVE-9999-0004"] == MatchStatus.POTENTIAL
