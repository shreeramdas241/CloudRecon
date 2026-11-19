"""Run the static discovery script through SSM. No SSH fallback and no shell injection."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from cloudrecon.discovery.host import parse_host_document
from cloudrecon.errors import CollectionError, CredentialError
from cloudrecon.models import HostInventory
from cloudrecon.security import require_instance_id, require_region
from cloudrecon.util import project_root


def load_collector_script() -> str:
    path = project_root() / "scripts" / "collect_host.sh"
    text = path.read_text(encoding="utf-8")
    if "\x00" in text:
        raise CollectionError("Collector script is invalid")
    return text


def build_ssm_request(instance_id: str, script_text: str) -> dict[str, Any]:
    require_instance_id(instance_id)
    return {
        "InstanceIds": [instance_id],
        "DocumentName": "AWS-RunShellScript",
        "Comment": "CloudRecon read-only inventory",
        "TimeoutSeconds": 300,
        "Parameters": {"commands": [script_text]},
    }


class SsmCollector:
    """Poll SSM for the static collector. The script text is not built from instance data."""

    def __init__(self, session: Any, sleeper: Any = time.sleep) -> None:
        self.session = session
        self.sleeper = sleeper
        self.script = load_collector_script()

    def collect(self, instance_id: str, region: str, attempts: int = 10) -> HostInventory:
        require_instance_id(instance_id)
        require_region(region)
        client = self.session.client("ssm", region_name=region)
        try:
            response = client.send_command(**build_ssm_request(instance_id, self.script))
        except Exception as exc:
            if "credentials" in str(exc).lower():
                raise CredentialError("No AWS credentials available for SSM") from exc
            raise CollectionError(f"SSM send_command failed for {instance_id}: {exc}") from exc
        command_id = response["Command"]["CommandId"]
        last = "Pending"
        for _ in range(attempts):
            self.sleeper(0)
            try:
                invocation = client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "") if hasattr(exc, "response") else ""
                if code == "InvocationDoesNotExist":
                    continue
                raise CollectionError(f"SSM invocation lookup failed: {exc}") from exc
            last = invocation.get("Status", "")
            if last in {"Success", "Failed", "Cancelled", "TimedOut"}:
                stdout = invocation.get("StandardOutputContent", "")
                if last != "Success":
                    raise CollectionError(
                        f"SSM collector status {last} for {instance_id}: "
                        f"{invocation.get('StandardErrorContent', '')[:500]}"
                    )
                return parse_host_document(stdout)
        raise CollectionError(f"SSM collector still {last} for {instance_id}")


def script_path() -> Path:
    return project_root() / "scripts" / "collect_host.sh"
