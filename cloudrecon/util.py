"""Small shared helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def isoformat(value: datetime | None = None) -> str:
    current = value or utcnow()
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.isoformat()


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return project_root() / path


def dump_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, default=str)


def load_json(payload: str | None, fallback: Any) -> Any:
    if not payload:
        return fallback
    return json.loads(payload)


def shift(value: datetime, days: int = 0, seconds: int = 0) -> datetime:
    return value + timedelta(days=days, seconds=seconds)
