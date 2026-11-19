"""Redaction, identifier checks, and safe command construction."""

from __future__ import annotations

import re
from typing import Any

from cloudrecon.errors import ScopeError

INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
REGION_RE = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
ACCOUNT_RE = re.compile(r"^\d{12}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SECRET_KEY = re.compile(
    r"(password|secret|token|authorization|api[_-]?key|session|credential)",
    re.IGNORECASE,
)
_AKIA = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_ASSIGNMENT = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|aws_secret_access_key|aws_session_token)"
    r"(\s*[:=]\s*)(\S+)"
)


def require_instance_id(value: str) -> str:
    if not INSTANCE_ID_RE.match(value or ""):
        raise ScopeError(f"Invalid EC2 instance id: {value!r}")
    return value


def require_region(value: str) -> str:
    if not REGION_RE.match(value or ""):
        raise ScopeError(f"Invalid AWS region: {value!r}")
    return value


def require_account(value: str) -> str:
    if not ACCOUNT_RE.match(value or ""):
        raise ScopeError(f"Invalid AWS account id: {value!r}")
    return value


def require_cve(value: str) -> str:
    if not CVE_RE.match(value or ""):
        raise ScopeError(f"Invalid CVE id: {value!r}")
    return value.upper()


def redact_text(value: str) -> str:
    cleaned = _ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}***", value)
    return _AKIA.sub("AKIA***REDACTED", cleaned)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)):
                cleaned[str(key)] = "***"
            else:
                cleaned[str(key)] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def safe_nmap_argv(target: str, ports: list[int]) -> list[str]:
    """Build a connect-scan argument list. The caller must already authorize it."""
    if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", target):
        raise ScopeError(f"Nmap target contains unsupported characters: {target!r}")
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ScopeError("Nmap ports must be an explicit list of valid port numbers")
    port_arg = ",".join(str(port) for port in sorted(set(ports)))
    return ["nmap", "-sT", "-Pn", "-n", "-p", port_arg, target]
