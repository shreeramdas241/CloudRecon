"""Synthetic fleet used by demo mode and the end-to-end test.

Instance identifiers and account 111122223333 are fictional. CVE-9999-* advisories
are illustrative. CVE-2021-44228 uses the published Log4j fix boundary of 2.15.0
and is still attached to a synthetic instance.
"""

from __future__ import annotations

from cloudrecon.models import (
    Asset,
    HostInventory,
    IngressRule,
    LoadBalancerRef,
    PackageRecord,
    SecurityGroup,
    ServiceRecord,
)

ACCOUNT = "111122223333"


def _pkg(name: str, version: str, manager: str, release: str = "") -> PackageRecord:
    return PackageRecord(name=name, version=version, release=release, manager=manager, epoch="0")


def _rule(protocol: str, start: int, end: int, cidrs: list[str]) -> IngressRule:
    return IngressRule(protocol=protocol, from_port=start, to_port=end, cidrs=cidrs)


def _asset(
    suffix: str,
    *,
    region: str,
    name: str,
    environment: str,
    criticality: str,
    private_ip: str,
    public_ip: str | None,
    subnet: str,
    igw: bool | None,
    groups: list[SecurityGroup],
    balancers: list[LoadBalancerRef] | None = None,
    ssm: bool | None = True,
    state: str = "running",
) -> Asset:
    instance_id = f"i-0aaa00000000000{suffix}"
    return Asset(
        asset_id=f"{ACCOUNT}/{region}/{instance_id}",
        account_id=ACCOUNT,
        region=region,
        instance_id=instance_id,
        name=name,
        instance_type="t3.small",
        state=state,
        private_ip=private_ip,
        public_ip=public_ip,
        ami_id="ami-0demo00000000001",
        vpc_id=f"vpc-demo{suffix}",
        subnet_id=subnet,
        iam_profile=f"arn:aws:iam::{ACCOUNT}:instance-profile/demo-read",
        ssm_managed=ssm,
        ssm_ping_status="Online" if ssm else "ConnectionLost",
        launch_time="2024-11-01T00:00:00+00:00",
        environment=environment,
        criticality=criticality,
        security_groups=groups,
        tags={
            "Name": name,
            "Environment": environment,
            "Criticality": criticality,
            "CloudRecon": "authorized",
        },
        has_igw_route=igw,
        load_balancers=balancers or [],
        sg_collected=True,
    )


def demo_assets() -> list[Asset]:
    web_sg = SecurityGroup(
        group_id="sg-demo0001",
        group_name="demo-web",
        ingress=[_rule("tcp", 443, 443, ["0.0.0.0/0"]), _rule("tcp", 22, 22, ["10.0.0.0/8"])],
    )
    app_sg = SecurityGroup(
        group_id="sg-demo0002",
        group_name="demo-app",
        ingress=[_rule("tcp", 8080, 8080, ["10.0.0.0/8"])],
    )
    dev_sg = SecurityGroup(
        group_id="sg-demo0003",
        group_name="demo-dev-http",
        ingress=[_rule("tcp", 80, 80, ["0.0.0.0/0"])],
    )
    ssh_sg = SecurityGroup(
        group_id="sg-demo0004",
        group_name="demo-ssh-world",
        ingress=[_rule("tcp", 22, 22, ["0.0.0.0/0"])],
    )
    private_sg = SecurityGroup(
        group_id="sg-demo0005",
        group_name="demo-private",
        ingress=[_rule("tcp", 443, 443, ["10.0.0.0/8"])],
    )
    staging_sg = SecurityGroup(
        group_id="sg-demo0006",
        group_name="demo-staging",
        ingress=[_rule("tcp", 443, 443, ["10.1.0.0/16"])],
    )
    return [
        _asset(
            "1", region="us-east-1", name="demo-web-1", environment="production", criticality="high",
            private_ip="10.0.1.10", public_ip="203.0.113.10", subnet="subnet-demo1", igw=True, groups=[web_sg],
        ),
        _asset(
            "2", region="us-east-1", name="demo-app-1", environment="production", criticality="high",
            private_ip="10.0.1.20", public_ip=None, subnet="subnet-demo2", igw=False, groups=[app_sg],
            balancers=[LoadBalancerRef(name="demo-internal-alb", scheme="internal", ports=[8080])],
        ),
        _asset(
            "3", region="us-east-1", name="demo-dev-1", environment="development", criticality="low",
            private_ip="10.0.3.30", public_ip="203.0.113.30", subnet="subnet-demo3", igw=True, groups=[dev_sg],
            balancers=[LoadBalancerRef(name="demo-public-alb", scheme="internet-facing", ports=[80])],
        ),
        _asset(
            "4", region="eu-west-1", name="demo-unmanaged-1", environment="production", criticality="high",
            private_ip="10.2.1.40", public_ip="203.0.113.40", subnet="subnet-demo4", igw=None, groups=[ssh_sg],
            ssm=False,
        ),
        _asset(
            "5", region="eu-west-1", name="demo-partial-1", environment="production", criticality="medium",
            private_ip="10.2.1.50", public_ip=None, subnet="subnet-demo5", igw=False, groups=[private_sg],
        ),
        _asset(
            "6", region="eu-west-1", name="demo-staging-1", environment="staging", criticality="medium",
            private_ip="10.2.4.60", public_ip="203.0.113.60", subnet="subnet-demo6", igw=True, groups=[staging_sg],
        ),
    ]


def _host(
    when: str,
    *,
    status: str,
    complete: bool,
    os_id: str,
    version: str,
    packages: list[PackageRecord],
    services: list[ServiceRecord] | None = None,
    errors: list[str] | None = None,
) -> HostInventory:
    return HostInventory(
        collected_at=when,
        collection_status=status,
        packages_complete=complete,
        errors=errors or [],
        os={"id": os_id, "version_id": version, "kernel": "5.15.0-100-generic", "pretty_name": f"{os_id} {version}"},
        packages=packages,
        services=services or [],
        docker_status="not_installed",
        permissions_notes=["Collected without privilege escalation."],
    )


def _ubuntu_base(curl: str, libssl: str) -> list[PackageRecord]:
    return [
        _pkg("libssl3", libssl, "deb"),
        _pkg("curl", curl, "deb"),
        _pkg("nginx", "1.24.0-1ubuntu1", "deb"),
        _pkg("linux-image-5.15.0-100-generic", "5.15.0-100.110", "deb"),
    ]


def hosts_before(when: str) -> dict[str, HostInventory | None]:
    assets = {asset.name: asset.asset_id for asset in demo_assets()}
    return {
        assets["demo-web-1"]: _host(
            when, status="success", complete=True, os_id="ubuntu", version="22.04",
            packages=_ubuntu_base("7.81.0-1ubuntu1.14", "3.0.2-0ubuntu1.10"),
            services=[
                ServiceRecord(name="nginx", port=443, protocol="tcp", process="nginx", pid=100, address="0.0.0.0"),
                ServiceRecord(name="sshd", port=22, protocol="tcp", process="sshd", pid=80, address="0.0.0.0"),
            ],
        ),
        assets["demo-app-1"]: _host(
            when, status="success", complete=True, os_id="ubuntu", version="22.04",
            packages=[_pkg("log4j-core", "2.14.1", "application")],
            services=[
                ServiceRecord(name="java", port=8080, protocol="tcp", process="java", pid=200, address="10.0.1.20")
            ],
        ),
        assets["demo-dev-1"]: _host(
            when, status="success", complete=True, os_id="amzn", version="2023",
            packages=[_pkg("httpd", "2.4.58-1.amzn2023.0.1", "rpm")],
            services=[
                ServiceRecord(name="httpd", port=80, protocol="tcp", process="httpd", pid=300, address="0.0.0.0")
            ],
        ),
        assets["demo-unmanaged-1"]: None,
        assets["demo-partial-1"]: _host(
            when, status="success", complete=True, os_id="ubuntu", version="22.04",
            packages=[_pkg("curl", "7.81.0-1ubuntu1.14", "deb")],
        ),
        assets["demo-staging-1"]: _host(
            when, status="success", complete=True, os_id="ubuntu", version="22.04",
            packages=[
                _pkg("libssl3", "3.0.2-0ubuntu1.18", "deb"),
                _pkg("nginx", "1.18.0-1ubuntu1", "deb"),
            ],
            services=[
                ServiceRecord(name="nginx", port=443, protocol="tcp", process="nginx", pid=400, address="0.0.0.0")
            ],
        ),
    }


def hosts_after(when: str) -> dict[str, HostInventory | None]:
    current = hosts_before(when)
    assets = {asset.name: asset.asset_id for asset in demo_assets()}
    current[assets["demo-web-1"]] = _host(
        when, status="success", complete=True, os_id="ubuntu", version="22.04",
        packages=_ubuntu_base("7.81.0-1ubuntu1.20", "3.0.2-0ubuntu1.10"),
        services=[
            ServiceRecord(name="nginx", port=443, protocol="tcp", process="nginx", pid=100, address="0.0.0.0"),
            ServiceRecord(name="sshd", port=22, protocol="tcp", process="sshd", pid=80, address="0.0.0.0"),
        ],
    )
    current[assets["demo-partial-1"]] = _host(
        when, status="failed", complete=False, os_id="ubuntu", version="22.04", packages=[],
        errors=["dpkg-query exited 1: permission denied while reading package status"],
    )
    return current
