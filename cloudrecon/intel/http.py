"""HTTP helpers with timeout, retry, and a SQLite-free in-memory/file cache."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from typing import Any

import httpx

from cloudrecon.errors import IntelError
from cloudrecon.util import isoformat, parse_time, utcnow


class ResponseCache:
    def __init__(self, store: dict[str, Any] | None = None) -> None:
        self.store = store if store is not None else {}

    def get(self, key: str) -> Any | None:
        row = self.store.get(key)
        if not row:
            return None
        stored = parse_time(row["stored_at"])
        if (utcnow() - stored).total_seconds() > row["ttl_seconds"]:
            return None
        return row["payload"]

    def set(self, key: str, payload: Any, ttl_seconds: int) -> None:
        self.store[key] = {
            "payload": payload,
            "stored_at": isoformat(),
            "ttl_seconds": ttl_seconds,
        }


def cache_key(method: str, url: str, body: Any = None) -> str:
    raw = json.dumps({"method": method, "url": url, "body": body}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def request_json(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    json_body: Any = None,
    headers: dict[str, str] | None = None,
    cache: ResponseCache | None = None,
    ttl_seconds: int = 86_400,
    attempts: int = 3,
    sleeper: Callable[[float], None] = time.sleep,
) -> Any:
    key = cache_key(method, url, json_body)
    if cache is not None:
        cached = cache.get(key)
        if cached is not None:
            return cached
    delay = 0.5
    last_error = "no response"
    for attempt in range(attempts):
        try:
            response = client.request(method, url, json=json_body, headers=headers, timeout=client.timeout)
        except httpx.TimeoutException as exc:
            last_error = f"timeout: {exc}"
            sleeper(delay)
            delay *= 2
            continue
        except httpx.HTTPError as exc:
            last_error = str(exc)
            sleeper(delay)
            delay *= 2
            continue
        if response.status_code == 429 or response.status_code >= 500:
            last_error = f"HTTP {response.status_code}"
            retry_after = response.headers.get("Retry-After")
            pause = float(retry_after) if retry_after and retry_after.isdigit() else delay
            sleeper(pause)
            delay *= 2
            continue
        if response.status_code >= 400:
            raise IntelError(f"{method} {url} failed with HTTP {response.status_code}")
        payload = response.json()
        if cache is not None:
            cache.set(key, payload, ttl_seconds)
        return payload
    raise IntelError(f"{method} {url} failed after {attempts} attempts: {last_error}")
