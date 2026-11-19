"""Explicit authorization scope for live assessments."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from cloudrecon.errors import ScopeError
from cloudrecon.models import Asset
from cloudrecon.security import require_account, require_region

_TARGET = re.compile(r"^[A-Za-z0-9_.:\-]+$")


class Scope(BaseModel):
    accounts: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)
    instance_tags: dict[str, str] = Field(default_factory=dict)
    allow_nmap: bool = False
    nmap_targets: list[str] = Field(default_factory=list)


def load_scope(path: Path) -> Scope:
    if not path.exists():
        raise ScopeError(f"Scope file not found: {path}")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ScopeError("Scope file must be a mapping")
    scope = Scope.model_validate(loaded)
    if not scope.accounts or not scope.regions:
        raise ScopeError("Live scope requires at least one account id and one region")
    for account in scope.accounts:
        require_account(str(account))
    for region in scope.regions:
        require_region(region)
    for target in scope.nmap_targets:
        if not _TARGET.fullmatch(target):
            raise ScopeError(f"Unsupported nmap target in scope: {target!r}")
    return scope


def asset_in_scope(asset: Asset, scope: Scope) -> bool:
    if asset.account_id not in scope.accounts or asset.region not in scope.regions:
        return False
    return all(asset.tags.get(key) == value for key, value in scope.instance_tags.items())
