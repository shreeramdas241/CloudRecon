from cloudrecon.demo.fixtures import demo_assets, hosts_after
from cloudrecon.exposure.analyzer import analyze_exposure
from cloudrecon.intel.correlator import correlate
from cloudrecon.intel.feeds import load_intel_files
from cloudrecon.models import MatchStatus, SecurityGroup
from cloudrecon.risk.engine import load_rules, prioritize
from cloudrecon.util import project_root


def _rules():
    return load_rules(project_root() / "config" / "risk_rules.yaml")


def _intel():
    root = project_root() / "examples" / "intel"
    return load_intel_files(root / "vendor_advisories.json", root / "nvd_snapshot.json", root / "kev_snapshot.json")


def test_exposure_does_not_treat_public_ip_as_reachable() -> None:
    assets = {asset.name: asset for asset in demo_assets()}
    hosts = hosts_after("2026-01-15T00:00:00+00:00")
    web = analyze_exposure(assets["demo-web-1"], hosts[assets["demo-web-1"].asset_id])
    assert web.internet_potential is True
    assert web.verified_reachable is False
    reasons = " ".join(reason.lower() for reason in web.reasons)
    assert "not verified" in reasons
    assert any("nginx" in note for note in web.service_notes)
    staging = analyze_exposure(assets["demo-staging-1"], hosts[assets["demo-staging-1"].asset_id])
    assert staging.internet_potential is False
    assert "public IP alone" in " ".join(staging.reasons)
    private = analyze_exposure(assets["demo-app-1"], hosts[assets["demo-app-1"].asset_id])
    assert private.internet_potential is False
    unmanaged = analyze_exposure(assets["demo-unmanaged-1"], None)
    assert unmanaged.internet_potential is True
    assert unmanaged.verified_reachable is False
    assert any("not confirmed" in reason.lower() for reason in unmanaged.reasons)


def test_missing_security_groups_stay_unknown() -> None:
    asset = demo_assets()[0].model_copy(update={"sg_collected": False, "security_groups": []})
    result = analyze_exposure(asset, None)
    assert result.internet_potential is None
    assert "not collected" in result.summary.lower() or "incomplete" in result.summary.lower()


def test_unauthorized_probe_is_ignored() -> None:
    asset = demo_assets()[5]
    ignored = analyze_exposure(asset, None, probe_ports=[{"port": 443, "protocol": "tcp"}], probes_authorized=False)
    assert ignored.verified_reachable is False
    authorized_target = demo_assets()[0]
    verified = analyze_exposure(
        authorized_target, None, probe_ports=[{"port": 443, "protocol": "tcp"}], probes_authorized=True
    )
    assert verified.verified_reachable is True
    assert verified.internet_potential is True


def test_private_instance_with_internet_lb_is_potential() -> None:
    from cloudrecon.models import IngressRule, LoadBalancerRef

    asset = demo_assets()[1].model_copy(
        update={
            "load_balancers": [LoadBalancerRef(name="edge", scheme="internet-facing", ports=[443])],
            "security_groups": [
                SecurityGroup(
                    group_id="sg",
                    group_name="edge",
                    ingress=[IngressRule(protocol="tcp", from_port=8080, to_port=8080, cidrs=["0.0.0.0/0"])],
                )
            ],
            "has_igw_route": False,
            "public_ip": None,
        }
    )
    result = analyze_exposure(asset, None)
    assert result.internet_potential is True
    assert result.verified_reachable is False


def test_priority_is_explainable_and_not_labeled_as_cvss() -> None:
    rules = _rules()
    assets = {asset.name: asset for asset in demo_assets()}
    hosts = hosts_after("2026-01-15T00:00:00+00:00")
    app_host = hosts[assets["demo-app-1"].asset_id]
    match = next(item for item in correlate(app_host, _intel()) if item.cve_id == "CVE-2021-44228")
    ranked = prioritize(match, assets["demo-app-1"], analyze_exposure(assets["demo-app-1"], app_host), rules)
    assert ranked.priority_score == 95
    assert ranked.priority_band == "critical"
    assert "not CVSS" in ranked.priority_disclaimer
    assert any(factor.factor == "kev" and factor.points == 35 for factor in ranked.priority_factors)
    web_host = hosts[assets["demo-web-1"].asset_id]
    openssl = next(item for item in correlate(web_host, _intel()) if item.status == MatchStatus.CONFIRMED)
    web_ranked = prioritize(openssl, assets["demo-web-1"], analyze_exposure(assets["demo-web-1"], web_host), rules)
    assert web_ranked.priority_score == 65
    assert web_ranked.priority_band == "high"
    staging_host = hosts[assets["demo-staging-1"].asset_id]
    nginx = next(item for item in correlate(staging_host, _intel()) if item.cve_id == "CVE-9999-0004")
    exposure = analyze_exposure(assets["demo-staging-1"], staging_host)
    staged = prioritize(nginx, assets["demo-staging-1"], exposure, rules)
    assert staged.priority_score == 18.34
    assert staged.priority_band == "low"
    assert any(factor.factor == "match_confidence_multiplier" for factor in staged.priority_factors)
