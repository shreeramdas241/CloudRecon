"""Live NVD, OSV, and CISA KEV clients. Demo mode does not call them."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from cloudrecon.intel.feeds import KevRecord, NvdRecord, load_kev_document, parse_nvd_api, parse_osv_vuln
from cloudrecon.intel.http import ResponseCache, request_json
from cloudrecon.models import PackageRecord

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_URL = "https://api.osv.dev/v1/query"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class NvdClient:
    def __init__(
        self,
        client: httpx.Client,
        cache: ResponseCache | None = None,
        api_key: str = "",
        min_interval: float = 6,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client = client
        self.cache = cache or ResponseCache()
        self.api_key = api_key
        self.min_interval = 0 if api_key else min_interval
        self.sleeper = sleeper
        self._last = 0.0

    def get_cve(self, cve_id: str) -> NvdRecord | None:
        self._pace()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        payload = request_json(
            self.client,
            "GET",
            f"{NVD_URL}?cveId={cve_id}",
            headers=headers,
            cache=self.cache,
            sleeper=self.sleeper,
        )
        records = parse_nvd_api(payload)
        for record in records:
            if record.cve_id.upper() == cve_id.upper():
                return record
        return None

    def _pace(self) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        wait = self.min_interval - (now - self._last)
        if wait > 0:
            self.sleeper(wait)
        self._last = time.monotonic()


class OsvClient:
    def __init__(self, client: httpx.Client, cache: ResponseCache | None = None) -> None:
        self.client = client
        self.cache = cache or ResponseCache()

    def query(self, package: PackageRecord, ecosystem: str, version: str) -> list[Any]:
        body = {"package": {"name": package.name, "ecosystem": ecosystem}, "version": version}
        payload = request_json(self.client, "POST", OSV_URL, json_body=body, cache=self.cache)
        advisories = []
        for vuln in payload.get("vulns") or []:
            advisories.extend(parse_osv_vuln(vuln))
        return advisories


class KevClient:
    def __init__(self, client: httpx.Client, cache: ResponseCache | None = None) -> None:
        self.client = client
        self.cache = cache or ResponseCache()

    def catalog(self) -> dict[str, KevRecord]:
        payload = request_json(self.client, "GET", KEV_URL, cache=self.cache, ttl_seconds=43_200)
        return load_kev_document(payload)
