"""boto3 adapter for EC2, SSM, and optional Inspector reads.

This module performs no writes. It is not invoked by demo mode. Live use still
requires an explicit scope file and CLOUDRECON_ALLOW_LIVE_SCAN=true.
"""

from __future__ import annotations

from typing import Any

from cloudrecon.discovery.ec2 import RegionFailure, is_skippable_error
from cloudrecon.errors import CredentialError
from cloudrecon.models import LoadBalancerRef


class BotoInventoryBackend:
    def __init__(self, session: Any | None = None) -> None:
        self._session = session

    def session(self) -> Any:
        if self._session is not None:
            return self._session
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover
            raise CredentialError("boto3 is not installed") from exc
        self._session = boto3.Session()
        return self._session

    def account_id(self) -> str:
        try:
            identity = self.session().client("sts").get_caller_identity()
        except Exception as exc:
            _raise_credential_or_wrap(exc)
        return str(identity["Account"])

    def instances(self, region: str) -> list[dict[str, Any]]:
        client = self.session().client("ec2", region_name=region)
        try:
            paginator = client.get_paginator("describe_instances")
            rows: list[dict[str, Any]] = []
            filters = [
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                }
            ]
            for page in paginator.paginate(Filters=filters):
                for reservation in page.get("Reservations", []):
                    rows.extend(reservation.get("Instances", []))
            return rows
        except Exception as exc:
            _raise_region(region, exc)

    def ssm_status(self, region: str) -> dict[str, str] | None:
        client = self.session().client("ssm", region_name=region)
        try:
            paginator = client.get_paginator("describe_instance_information")
            status: dict[str, str] = {}
            for page in paginator.paginate():
                for item in page.get("InstanceInformationList", []):
                    status[item["InstanceId"]] = item.get("PingStatus", "")
            return status
        except Exception as exc:
            if _code(exc) in {"AccessDeniedException", "AccessDenied"}:
                return None
            _raise_region(region, exc)

    def security_groups(self, region: str, group_ids: list[str]) -> dict[str, dict[str, Any]] | None:
        client = self.session().client("ec2", region_name=region)
        found: dict[str, dict[str, Any]] = {}
        try:
            for start in range(0, len(group_ids), 100):
                chunk = group_ids[start : start + 100]
                response = client.describe_security_groups(GroupIds=chunk)
                for group in response.get("SecurityGroups", []):
                    found[group["GroupId"]] = group
            return found
        except Exception as exc:
            if _code(exc) in {"AccessDeniedException", "UnauthorizedOperation", "AccessDenied"}:
                return None
            _raise_region(region, exc)

    def route_has_igw(self, region: str, subnet_id: str) -> bool | None:
        client = self.session().client("ec2", region_name=region)
        try:
            tables = client.describe_route_tables(
                Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
            ).get("RouteTables", [])
            if not tables:
                tables = client.describe_route_tables(
                    Filters=[{"Name": "association.main", "Values": ["true"]}]
                ).get("RouteTables", [])
            if not tables:
                return None
            for table in tables:
                for route in table.get("Routes", []):
                    gateway = route.get("GatewayId", "")
                    if gateway.startswith("igw-") and route.get("DestinationCidrBlock") in {
                        "0.0.0.0/0",
                        "::/0",
                    }:
                        return True
            return False
        except Exception as exc:
            if _code(exc) in {"AccessDeniedException", "UnauthorizedOperation", "AccessDenied"}:
                return None
            _raise_region(region, exc)

    def load_balancers_for_instances(self, region: str) -> dict[str, list[LoadBalancerRef]] | None:
        try:
            elb = self.session().client("elbv2", region_name=region)
            balancers = elb.describe_load_balancers().get("LoadBalancers", [])
            target_groups = elb.describe_target_groups().get("TargetGroups", [])
        except Exception as exc:
            if _code(exc) in {"AccessDeniedException", "UnauthorizedOperation", "AccessDenied"}:
                return None
            _raise_region(region, exc)
        schemes = {item["LoadBalancerArn"]: item for item in balancers}
        mapping: dict[str, list[LoadBalancerRef]] = {}
        for group in target_groups:
            arn = group.get("LoadBalancerArns", [None])[0] if group.get("LoadBalancerArns") else None
            parent = schemes.get(arn) if arn else None
            if parent is None:
                continue
            health = elb.describe_target_health(TargetGroupArn=group["TargetGroupArn"])
            for target in health.get("TargetHealthDescriptions", []):
                instance_id = (target.get("Target") or {}).get("Id", "")
                if not instance_id.startswith("i-"):
                    continue
                mapping.setdefault(instance_id, []).append(
                    LoadBalancerRef(
                        name=parent.get("LoadBalancerName", ""),
                        scheme=parent.get("Scheme", ""),
                        ports=[group.get("Port")] if group.get("Port") else [],
                    )
                )
        return mapping


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str((response.get("Error") or {}).get("Code", ""))
    return exc.__class__.__name__


def _raise_region(region: str, exc: Exception) -> None:
    code = _code(exc)
    if is_skippable_error(code):
        raise RegionFailure(region, code, str(exc)) from exc
    if code in {"NoCredentialsError", "PartialCredentialsError"}:
        raise CredentialError("No AWS credentials available in the credential chain") from exc
    raise RegionFailure(region, code or "Error", str(exc)) from exc


def _raise_credential_or_wrap(exc: Exception) -> None:
    code = _code(exc)
    if code in {"NoCredentialsError", "PartialCredentialsError"} or "credentials" in str(exc).lower():
        raise CredentialError("No AWS credentials available in the credential chain") from exc
    raise CredentialError(f"AWS identity lookup failed ({code or exc.__class__.__name__})") from exc
