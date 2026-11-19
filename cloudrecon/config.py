"""Configuration loading. Secrets come from the environment, never from code."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

from cloudrecon.util import project_root, resolve_path


class Settings(BaseSettings):
    """Runtime settings.

    `load_settings` applies config/settings.yaml and then lets environment
    variables win. AWS access keys are intentionally absent: boto3 uses its
    own credential chain.
    """

    model_config = SettingsConfigDict(extra="ignore")

    mode: str = "demo"
    database_path: str = "data/cloudrecon.db"
    intel_offline: bool = True
    allow_live_scan: bool = False
    allow_nmap: bool = False
    enable_inspector: bool = False
    enable_jira: bool = False
    jira_base_url: str = ""
    jira_email: str = ""
    jira_api_token: str = ""
    jira_project: str = ""
    webhook_url: str = ""
    nvd_api_key: str = ""
    log_level: str = "INFO"
    nvd_min_interval_seconds: float = 6
    http_timeout_seconds: float = 20
    scheduler_interval_seconds: int = 86400
    scheduler_backoff_seconds: int = 30
    advisory_path: str = "examples/intel/vendor_advisories.json"
    kev_path: str = "examples/intel/kev_snapshot.json"
    nvd_snapshot_path: str = "examples/intel/nvd_snapshot.json"
    risk_rules_path: str = "config/risk_rules.yaml"
    scope_path: str = "config/scope.example.yaml"
    report_dir: str = "examples/reports"

    def path_for(self, value: str) -> Path:
        return resolve_path(value)

    @property
    def database(self) -> Path:
        return self.path_for(self.database_path)

    @property
    def live_enabled(self) -> bool:
        return self.mode == "live" and self.allow_live_scan


def load_settings() -> Settings:
    data: dict[str, object] = {}
    settings_file = project_root() / "config" / "settings.yaml"
    if settings_file.exists():
        loaded = yaml.safe_load(settings_file.read_text(encoding="utf-8")) or {}
        if isinstance(loaded, dict):
            data.update(loaded)
    env_file = project_root() / ".env"
    if env_file.exists():
        _load_env_file(env_file)
    prefix = "CLOUDRECON_"
    for key, value in os.environ.items():
        if key.startswith(prefix):
            data[key[len(prefix) :].lower()] = value
    return Settings(**data)


def _load_env_file(path: Path) -> None:
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
