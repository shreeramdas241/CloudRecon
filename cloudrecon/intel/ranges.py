"""OSV-style range evaluation."""

from __future__ import annotations

from cloudrecon.errors import VersionCompareError
from cloudrecon.versioning import version_compare


def evaluate_events(version: str, events: list[dict[str, str]], style: str) -> str:
    """Return affected, not_affected, or unknown.

    Events are applied in order, matching the OSV specification: a version is
    affected when it has reached an `introduced` event and has not reached a
    later `fixed` or passed `last_affected`.
    """
    if not events:
        return "unknown"
    affected = False
    seen = False
    try:
        for event in events:
            if event.get("introduced") is not None:
                seen = True
                if version_compare(version, event["introduced"], style) >= 0:
                    affected = True
            elif event.get("fixed") is not None:
                seen = True
                if version_compare(version, event["fixed"], style) >= 0:
                    affected = False
            elif event.get("last_affected") is not None:
                seen = True
                if version_compare(version, event["last_affected"], style) > 0:
                    affected = False
    except VersionCompareError:
        return "unknown"
    if not seen:
        return "unknown"
    return "affected" if affected else "not_affected"


def bounds_match(
    version: str,
    *,
    style: str,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
) -> str:
    if not any([start_including, start_excluding, end_including, end_excluding]):
        return "unknown"
    try:
        if start_including and version_compare(version, start_including, style) < 0:
            return "not_affected"
        if start_excluding and version_compare(version, start_excluding, style) <= 0:
            return "not_affected"
        if end_including and version_compare(version, end_including, style) > 0:
            return "not_affected"
        if end_excluding and version_compare(version, end_excluding, style) >= 0:
            return "not_affected"
    except VersionCompareError:
        return "unknown"
    return "affected"


def describe_events(events: list[dict[str, str]]) -> str:
    parts: list[str] = []
    for event in events:
        for key in ("introduced", "fixed", "last_affected"):
            if event.get(key) is not None:
                parts.append(f"{key} {event[key]}")
    return ", ".join(parts)


def fixed_version(events: list[dict[str, str]]) -> str | None:
    for event in events:
        if event.get("fixed"):
            return event["fixed"]
    return None
