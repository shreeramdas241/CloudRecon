"""Separate potential network exposure from verified reachability.

A public IP or a world-open security group is not treated as confirmed internet
reachability. Missing security group data stays unknown rather than safe.
"""

from __future__ import annotations

from typing import Any

from cloudrecon.models import Asset, ExposureAssessment, HostInventory, IngressRule

_WORLD = {"0.0.0.0/0", "::/0"}


def analyze_exposure(
    asset: Asset,
    host: HostInventory | None = None,
    probe_ports: list[dict[str, Any]] | None = None,
    probes_authorized: bool = False,
) -> ExposureAssessment:
    reasons: list[str] = []
    world_ports: list[dict[str, Any]] = []
    sg_open: bool | None
    if not asset.sg_collected:
        sg_open = None
        reasons.append("Security group rules were not collected, so exposure cannot be decided.")
    else:
        unknown_rule = False
        for group in asset.security_groups:
            for rule in group.ingress:
                kind, ports = _classify(rule)
                if kind == "world":
                    world_ports.append(
                        {
                            "group_id": group.group_id,
                            "protocol": rule.protocol,
                            "from_port": rule.from_port,
                            "to_port": rule.to_port,
                            "cidrs": rule.cidrs,
                        }
                    )
                elif kind == "unknown":
                    unknown_rule = True
                    reasons.append(
                        f"{group.group_id} has an ingress rule that references a prefix list or "
                        "security group and was not expanded."
                    )
        if world_ports:
            sg_open = True
            reasons.append("At least one ingress rule allows 0.0.0.0/0 or ::/0.")
        elif unknown_rule:
            sg_open = None
        else:
            sg_open = False
            reasons.append("No collected ingress rule allows 0.0.0.0/0 or ::/0.")

    internet_lb = [item for item in asset.load_balancers if item.scheme == "internet-facing"]
    internal_lb = [item for item in asset.load_balancers if item.scheme == "internal"]
    if internet_lb:
        reasons.append(
            "Attached to internet-facing load balancer(s): " + ", ".join(item.name for item in internet_lb) + "."
        )
    if internal_lb:
        reasons.append(
            "Attached to internal load balancer(s): " + ", ".join(item.name for item in internal_lb) + "."
        )
    if asset.public_ip:
        reasons.append(f"Instance has public IP {asset.public_ip}.")
    else:
        reasons.append("No public IP was observed on the instance.")
    if asset.has_igw_route is True:
        reasons.append("The subnet route table has a default route to an internet gateway.")
    elif asset.has_igw_route is False:
        reasons.append("The subnet route table has no default route to an internet gateway.")
    else:
        reasons.append("Internet gateway route state is unknown.")

    addressable = bool(asset.public_ip) or bool(internet_lb)
    if sg_open is None:
        potential: bool | None = None
    elif sg_open and addressable and asset.has_igw_route is not False:
        potential = True
        reasons.append(
            "Potential internet exposure: a world-open rule coincides with a public IP "
            "or internet-facing load balancer. This is not verified reachability."
        )
        if asset.has_igw_route is None and asset.public_ip:
            reasons.append("The internet-gateway route was not confirmed.")
    elif sg_open and asset.has_igw_route is False and internet_lb:
        potential = True
        reasons.append("Potential exposure is via the internet-facing load balancer, not the instance route table.")
    else:
        potential = False
        if sg_open and not addressable:
            reasons.append(
                "The security group is permissive, and no public IP or internet-facing load balancer was observed."
            )
        if asset.public_ip and sg_open is False:
            reasons.append("A public IP alone is not treated as internet exposure.")
        if asset.public_ip and asset.has_igw_route is False:
            reasons.append("A public IP without an internet-gateway route is not treated as exposed.")

    verified = False
    if probe_ports and not probes_authorized:
        reasons.append("Probe results were ignored because external scanning is not authorized.")
    elif probe_ports and probes_authorized:
        verified = True
        potential = True
        reasons.append(
            "Authorized probe reported open ports: "
            + ", ".join(f"{item.get('port')}/{item.get('protocol')}" for item in probe_ports)
            + ". This is verified reachability for those ports only."
        )

    notes = _service_notes(host, world_ports) if host else []
    summary = _summary(potential, verified, sg_open)
    return ExposureAssessment(
        asset_id=asset.asset_id,
        internet_potential=potential,
        verified_reachable=verified,
        sg_open_to_world=sg_open,
        summary=summary,
        reasons=reasons,
        world_ports=world_ports,
        service_notes=notes,
    )


def _classify(rule: IngressRule) -> tuple[str, str]:
    world = any(cidr in _WORLD for cidr in rule.cidrs)
    if world:
        return "world", ""
    if rule.unknown and not rule.cidrs:
        return "unknown", ""
    if rule.unknown:
        return "unknown", ""
    return "restricted", ""


def _service_notes(host: HostInventory, world_ports: list[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    for service in host.services:
        if service.port is None:
            continue
        for rule in world_ports:
            if _port_allowed(service.port, rule):
                notes.append(
                    f"{service.name or service.process or 'service'} listens on {service.port}/{service.protocol} "
                    f"and security group {rule['group_id']} allows that port from the world. "
                    "Listening state is not the same as confirmed external reachability."
                )
                break
    return notes


def _port_allowed(port: int, rule: dict[str, Any]) -> bool:
    if str(rule.get("protocol")) == "-1":
        return True
    start = rule.get("from_port")
    end = rule.get("to_port")
    if start is None or end is None:
        return True
    return start <= port <= end


def _summary(potential: bool | None, verified: bool, sg_open: bool | None) -> str:
    if verified:
        return "Verified reachable on authorized probe ports. Other paths are not implied."
    if potential is True:
        return "Potentially internet exposed. Reachability was not verified."
    if potential is False:
        return "No potential internet path was identified from the collected AWS data."
    if sg_open is None:
        return "Exposure is unknown because required AWS network data is incomplete."
    return "Exposure is unknown."
