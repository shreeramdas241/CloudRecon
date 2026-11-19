"""Parse read-only host inventory produced by scripts/collect_host.sh."""

from __future__ import annotations

import json
from typing import Any

from cloudrecon.errors import CollectionError
from cloudrecon.models import HostInventory, PackageRecord, ServiceRecord
from cloudrecon.security import redact_text

MAX_HOST_BYTES = 20_000_000
MAX_PACKAGES = 20_000
MAX_SERVICES = 10_000


def parse_host_document(raw: str | bytes | dict[str, Any]) -> HostInventory:
    if isinstance(raw, dict):
        payload = raw
    else:
        data = raw if isinstance(raw, bytes) else raw.encode("utf-8")
        if len(data) > MAX_HOST_BYTES:
            raise CollectionError("Host inventory exceeds the 20 MB parser limit")
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise CollectionError(f"Host inventory is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CollectionError("Host inventory JSON must be an object")
    status = str(payload.get("collection_status") or "unknown")
    packages_complete = bool(payload.get("packages_complete")) and status == "success"
    packages = _packages(payload.get("packages"))
    if len(packages) > MAX_PACKAGES:
        raise CollectionError("Host inventory package list exceeds the parser limit")
    services = _services(payload.get("services"))
    if len(services) > MAX_SERVICES:
        raise CollectionError("Host inventory service list exceeds the parser limit")
    errors = [redact_text(str(item)) for item in payload.get("errors") or []]
    if status != "success":
        packages_complete = False
    return HostInventory(
        schema_version=str(payload.get("schema_version") or "1.0"),
        collected_at=str(payload.get("collected_at") or ""),
        collection_status=status,
        packages_complete=packages_complete,
        errors=errors,
        os={str(key): str(value) for key, value in (payload.get("os") or {}).items()},
        packages=packages,
        services=services,
        processes=[_redact_mapping(item) for item in payload.get("processes") or [] if isinstance(item, dict)],
        docker=[item for item in payload.get("docker") or [] if isinstance(item, dict)],
        docker_status=str(payload.get("docker_status") or "not_collected"),
        processes_truncated=bool(payload.get("processes_truncated")),
        permissions_notes=[str(item) for item in payload.get("permissions_notes") or []],
    )


def _packages(value: Any) -> list[PackageRecord]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise CollectionError("packages must be a list when present")
    records: list[PackageRecord] = []
    for item in value:
        if not isinstance(item, dict) or not item.get("name") or not item.get("version"):
            raise CollectionError("Each package needs a name and version")
        records.append(PackageRecord.model_validate(item))
    return records


def _services(value: Any) -> list[ServiceRecord]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise CollectionError("services must be a list when present")
    return [ServiceRecord.model_validate(item) for item in value if isinstance(item, dict)]


def _redact_mapping(item: dict[str, Any]) -> dict[str, Any]:
    return {str(key): redact_text(value) if isinstance(value, str) else value for key, value in item.items()}
