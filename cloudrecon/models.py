"""Domain models shared by collectors, correlation, storage, and the API."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MatchStatus(StrEnum):
    CONFIRMED = "confirmed_affected"
    POTENTIAL = "potentially_affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


class RemediationStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "under_investigation"
    IN_PROGRESS = "remediation_in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


OPEN_REMEDIATION = {
    RemediationStatus.OPEN,
    RemediationStatus.INVESTIGATING,
    RemediationStatus.IN_PROGRESS,
}
MANUAL_REMEDIATION = {
    RemediationStatus.OPEN,
    RemediationStatus.INVESTIGATING,
    RemediationStatus.IN_PROGRESS,
    RemediationStatus.ACCEPTED,
    RemediationStatus.FALSE_POSITIVE,
}


class PackageRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    version: str
    release: str = ""
    epoch: str = "0"
    arch: str = ""
    manager: str
    source: str = ""


class ServiceRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    port: int | None = None
    protocol: str = "tcp"
    process: str = ""
    pid: int | None = None
    executable: str = ""
    address: str = ""


class HostInventory(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: str = "1.0"
    collected_at: str
    collection_status: str
    packages_complete: bool = False
    errors: list[str] = Field(default_factory=list)
    os: dict[str, str] = Field(default_factory=dict)
    packages: list[PackageRecord] = Field(default_factory=list)
    services: list[ServiceRecord] = Field(default_factory=list)
    processes: list[dict[str, Any]] = Field(default_factory=list)
    docker: list[dict[str, Any]] = Field(default_factory=list)
    docker_status: str = "not_collected"
    processes_truncated: bool = False
    permissions_notes: list[str] = Field(default_factory=list)


class IngressRule(BaseModel):
    protocol: str
    from_port: int | None = None
    to_port: int | None = None
    cidrs: list[str] = Field(default_factory=list)
    unknown: bool = False


class SecurityGroup(BaseModel):
    group_id: str
    group_name: str = ""
    ingress: list[IngressRule] = Field(default_factory=list)


class LoadBalancerRef(BaseModel):
    name: str
    scheme: str
    ports: list[int] = Field(default_factory=list)


class Asset(BaseModel):
    asset_id: str
    account_id: str
    region: str
    instance_id: str
    name: str = ""
    instance_type: str = ""
    state: str = ""
    private_ip: str | None = None
    public_ip: str | None = None
    ami_id: str = ""
    vpc_id: str = ""
    subnet_id: str = ""
    iam_profile: str = ""
    ssm_managed: bool | None = None
    ssm_ping_status: str = ""
    launch_time: str = ""
    environment: str = ""
    criticality: str = ""
    security_groups: list[SecurityGroup] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    has_igw_route: bool | None = None
    load_balancers: list[LoadBalancerRef] = Field(default_factory=list)
    sg_collected: bool = False


class Evidence(BaseModel):
    source: str
    detail: str
    advisory_id: str = ""
    illustrative: bool = False


class CorrelationResult(BaseModel):
    status: MatchStatus
    confidence: float
    cve_id: str
    package_name: str
    installed_version: str
    affected_versions: str
    fixed_version: str | None = None
    sources: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    cvss: float | None = None
    severity: str | None = None
    kev: bool = False
    kev_detail: dict[str, Any] = Field(default_factory=dict)
    version_style: str = ""


class PriorityFactor(BaseModel):
    factor: str
    points: float
    detail: str


class PrioritizedFinding(BaseModel):
    correlation: CorrelationResult
    asset_id: str
    priority_band: str
    priority_score: float
    priority_factors: list[PriorityFactor]
    priority_disclaimer: str


class ExposureAssessment(BaseModel):
    asset_id: str
    internet_potential: bool | None
    verified_reachable: bool = False
    sg_open_to_world: bool | None
    summary: str
    reasons: list[str] = Field(default_factory=list)
    world_ports: list[dict[str, Any]] = Field(default_factory=list)
    service_notes: list[str] = Field(default_factory=list)


class ScanRecord(BaseModel):
    id: str
    mode: str
    status: str
    started_at: str
    finished_at: str | None = None
    scope: str = ""
    stats: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    demo: bool = False


class FindingRecord(BaseModel):
    id: str
    fingerprint: str
    asset_id: str
    cve_id: str
    package_name: str
    installed_version: str
    affected_versions: str = ""
    fixed_version: str | None = None
    advisory_sources: list[str] = Field(default_factory=list)
    cvss: float | None = None
    severity: str | None = None
    kev: bool = False
    kev_detail: dict[str, Any] = Field(default_factory=dict)
    match_status: str
    confidence: float
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    priority_band: str | None = None
    priority_score: float | None = None
    priority_explanation: list[dict[str, Any]] = Field(default_factory=list)
    priority_disclaimer: str = ""
    remediation_status: str
    first_seen: str
    last_seen: str
    resolved_at: str | None = None
    last_scan_id: str | None = None
    status_note: str = ""
    demo: bool = False
    illustrative: bool = False
    region: str = ""
    asset_name: str = ""
    environment: str = ""
