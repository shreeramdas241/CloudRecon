"""Optional webhook and Jira notifications. Both are inert until configured."""

from __future__ import annotations

import httpx

from cloudrecon.config import Settings
from cloudrecon.logging_utils import get_logger
from cloudrecon.security import redact

LOGGER = get_logger(__name__)


class NotificationService:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.client = client

    def scan_failed(self, scan_id: str, error: str) -> None:
        self._webhook({"event": "scan_failed", "scan_id": scan_id, "error": error})

    def findings_opened(self, findings: list[dict[str, str]]) -> None:
        self._webhook({"event": "findings_opened", "findings": findings})
        if self.settings.enable_jira:
            for finding in findings:
                self.create_jira_issue(finding)

    def create_jira_issue(self, finding: dict[str, str]) -> str | None:
        settings = self.settings
        if not settings.enable_jira:
            return None
        if not all([settings.jira_base_url, settings.jira_email, settings.jira_api_token, settings.jira_project]):
            LOGGER.warning("Jira is enabled but the base URL, email, token, or project is missing")
            return None
        payload = {
            "fields": {
                "project": {"key": settings.jira_project},
                "summary": f"[CloudRecon] {finding.get('cve_id')} on {finding.get('asset_id')}",
                "issuetype": {"name": "Task"},
                "description": redact(
                    {
                        "cve": finding.get("cve_id"),
                        "asset": finding.get("asset_id"),
                        "package": finding.get("package"),
                        "priority": finding.get("priority"),
                        "note": "Created by CloudRecon. Remediation is not automatic.",
                    }
                ),
            }
        }
        url = settings.jira_base_url.rstrip("/") + "/rest/api/3/issue"
        try:
            response = self._client().post(url, json=payload, auth=(settings.jira_email, settings.jira_api_token))
            response.raise_for_status()
        except httpx.HTTPError as exc:
            LOGGER.warning("Jira issue creation failed: %s", exc.__class__.__name__)
            return None
        return str(response.json().get("key", "")) or None

    def _webhook(self, payload: dict) -> None:
        if not self.settings.webhook_url:
            return
        try:
            self._client().post(self.settings.webhook_url, json=redact(payload))
        except httpx.HTTPError as exc:
            LOGGER.warning("Webhook notification failed: %s", exc.__class__.__name__)

    def _client(self) -> httpx.Client:
        if self.client is not None:
            return self.client
        self.client = httpx.Client(timeout=self.settings.http_timeout_seconds)
        return self.client
