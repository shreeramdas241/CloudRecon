"""EC2 inventory parsing and multi-region collection.

The boto3 adapter is separate from parsing so tests can supply AWS-shaped
documents without credentials. A region that denies access is recorded and
skipped. It is not treated as an empty account.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from cloudrecon.errors import CredentialError
from cloudrecon.models import Asset, IngressRule, LoadBalancerRef, SecurityGroup
from cloudrecon.security import require_instance_id, require_region

_SKIP_CODES = {
    "AuthFailure",
    "UnauthorizedOperation",
    "AccessDenied",
    "AccessDeniedException",
    "OptInRequired",
    "UnrecognizedClientException",
    "InvalidClientTokenId",
}


class RegionFailure(Exception):
    def __init__(self, region: str, code: str, message: str) -> None:
        self.region = region
        self.code = code
        super().__init__(f"{region}: {code}: {message}")


class InventoryBackend(Protocol):
    def account_id(self) -> str: ...

    def instances(self, region: str) -> list[dict[str, Any]]: ...

    def ssm_status(self, region: str) -> dict[str, str] | None: ...

    def security_groups(self, region: str, group_ids: list[str]) -> dict[str, dict[str, Any]] | None: ...

    def route_has_igw(self, region: str, subnet_id: str) -> bool | None: ...

    def load_balancers_for_instances(self, region: str) -> dict[str, list[LoadBalancerRef]] | None: ...


class DiscoveryBundle:
    def __init__(self) -> None:
        self.assets: list[Asset] = []
        self.errors: list[str] = []


def discover(backend: InventoryBackend, regions: list[str]) -> DiscoveryBundle:
    bundle = DiscoveryBundle()
    try:
        account_id = backend.account_id()
    except CredentialError:
        raise
    except Exception as exc:
        raise CredentialError(f"Could not resolve AWS account id: {exc}") from exc
    for region in regions:
        require_region(region)
        try:
            raw_instances = backend.instances(region)
            ssm = backend.ssm_status(region)
            group_ids = sorted(
                {
                    group.get("GroupId", "")
                    for instance in raw_instances
                    for group in instance.get("SecurityGroups", [])
                    if group.get("GroupId")
                }
            )
            groups = backend.security_groups(region, group_ids) if group_ids else {}
            balancers = backend.load_balancers_for_instances(region)
        except RegionFailure as exc:
            bundle.errors.append(str(exc))
            continue
        except CredentialError:
            raise
        if groups is None:
            bundle.errors.append(f"{region}: security group rules could not be collected")
        if ssm is None:
            bundle.errors.append(f"{region}: SSM management status could not be collected")
        if balancers is None:
            bundle.errors.append(f"{region}: load balancer relationships could not be collected")
            balancers = {}
        for raw in raw_instances:
            asset = parse_instance(
                raw,
                account_id=account_id,
                region=region,
                ssm=ssm,
                groups=groups,
                balancers=balancers,
            )
            if asset.subnet_id:
                try:
                    asset.has_igw_route = backend.route_has_igw(region, asset.subnet_id)
                except RegionFailure as exc:
                    bundle.errors.append(str(exc))
                    asset.has_igw_route = None
            bundle.assets.append(asset)
    return bundle


def parse_instance(
    raw: dict[str, Any],
    *,
    account_id: str,
    region: str,
    ssm: dict[str, str] | None,
    groups: dict[str, dict[str, Any]] | None,
    balancers: dict[str, list[LoadBalancerRef]],
) -> Asset:
    instance_id = require_instance_id(raw["InstanceId"])
    tags = {item.get("Key", ""): item.get("Value", "") for item in raw.get("Tags", [])}
    name = tags.get("Name", "")
    environment = _tag(tags, "Environment", "env")
    criticality = _tag(tags, "Criticality", "criticality")
    profile = ""
    iam = raw.get("IamInstanceProfile") or {}
    profile = iam.get("Arn", "")
    ssm_managed: bool | None
    ping = ""
    if ssm is None:
        ssm_managed = None
    elif instance_id in ssm:
        ssm_managed = True
        ping = ssm[instance_id]
    else:
        ssm_managed = False
    security_groups, sg_collected = _security_groups(raw, groups)
    launch = raw.get("LaunchTime", "")
    if isinstance(launch, datetime):
        launch = launch.isoformat()
    return Asset(
        asset_id=f"{account_id}/{region}/{instance_id}",
        account_id=account_id,
        region=region,
        instance_id=instance_id,
        name=name,
        instance_type=raw.get("InstanceType", ""),
        state=(raw.get("State") or {}).get("Name", ""),
        private_ip=raw.get("PrivateIpAddress"),
        public_ip=raw.get("PublicIpAddress"),
        ami_id=raw.get("ImageId", ""),
        vpc_id=raw.get("VpcId", ""),
        subnet_id=raw.get("SubnetId", ""),
        iam_profile=profile,
        ssm_managed=ssm_managed,
        ssm_ping_status=ping,
        launch_time=str(launch),
        environment=environment.lower(),
        criticality=criticality.lower(),
        security_groups=security_groups,
        tags=tags,
        load_balancers=balancers.get(instance_id, []),
        sg_collected=sg_collected,
    )


def parse_security_group(raw: dict[str, Any]) -> SecurityGroup:
    rules: list[IngressRule] = []
    for permission in raw.get("IpPermissions", []):
        cidrs = [item.get("CidrIp", "") for item in permission.get("IpRanges", []) if item.get("CidrIp")]
        cidrs.extend(
            item.get("CidrIpv6", "") for item in permission.get("Ipv6Ranges", []) if item.get("CidrIpv6")
        )
        unknown = bool(permission.get("PrefixListIds") or permission.get("UserIdGroupPairs"))
        rules.append(
            IngressRule(
                protocol=str(permission.get("IpProtocol", "")),
                from_port=permission.get("FromPort"),
                to_port=permission.get("ToPort"),
                cidrs=sorted(set(cidrs)),
                unknown=unknown,
            )
        )
    return SecurityGroup(
        group_id=raw.get("GroupId", ""),
        group_name=raw.get("GroupName", ""),
        ingress=rules,
    )


def _security_groups(
    raw: dict[str, Any], groups: dict[str, dict[str, Any]] | None
) -> tuple[list[SecurityGroup], bool]:
    refs = raw.get("SecurityGroups", [])
    if groups is None:
        return [
            SecurityGroup(group_id=item.get("GroupId", ""), group_name=item.get("GroupName", ""))
            for item in refs
        ], False
    parsed: list[SecurityGroup] = []
    for item in refs:
        group_id = item.get("GroupId", "")
        detailed = groups.get(group_id)
        if detailed is None:
            parsed.append(SecurityGroup(group_id=group_id, group_name=item.get("GroupName", "")))
            return parsed, False
        parsed.append(parse_security_group(detailed))
    return parsed, True


def _tag(tags: dict[str, str], *names: str) -> str:
    folded = {key.lower(): value for key, value in tags.items()}
    for name in names:
        if name.lower() in folded:
            return folded[name.lower()]
    return ""


def is_skippable_error(code: str) -> bool:
    return code in _SKIP_CODES
