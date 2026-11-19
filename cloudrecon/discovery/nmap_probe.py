"""Optional authorized TCP connect check.

Disabled unless both the process setting and the scope file allow it, and the
target is on the scope allowlist. Results are verified reachability only when
those gates pass. This module does not run nmap unless `run_probe` is called.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from cloudrecon.errors import ScopeError
from cloudrecon.scope import Scope
from cloudrecon.security import safe_nmap_argv


def authorize_probe(scope: Scope, process_allowed: bool, target: str) -> None:
    if not process_allowed or not scope.allow_nmap:
        raise ScopeError("Nmap is disabled. Set the scope flag and CLOUDRECON_ALLOW_NMAP=true")
    if target not in scope.nmap_targets:
        raise ScopeError(f"{target} is not in the nmap allowlist")


def parse_nmap_xml(document: str) -> list[dict[str, str | int]]:
    try:
        root = ET.fromstring(document)
    except ET.ParseError as exc:
        raise ScopeError(f"Nmap XML could not be parsed: {exc}") from exc
    open_ports: list[dict[str, str | int]] = []
    for host in root.findall("host"):
        address = ""
        addr = host.find("address")
        if addr is not None:
            address = addr.attrib.get("addr", "")
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            open_ports.append(
                {
                    "address": address,
                    "protocol": port.attrib.get("protocol", "tcp"),
                    "port": int(port.attrib.get("portid", "0")),
                    "state": "open",
                }
            )
    return open_ports


def run_probe(scope: Scope, process_allowed: bool, target: str, ports: list[int]) -> list[dict[str, str | int]]:
    authorize_probe(scope, process_allowed, target)
    binary = shutil.which("nmap")
    if not binary:
        raise ScopeError("nmap is not installed on this operator host")
    argv = [binary, *safe_nmap_argv(target, ports)[1:], "-oX", "-"]
    completed = subprocess.run(argv, check=False, capture_output=True, text=True, shell=False, timeout=120)
    if completed.returncode != 0:
        raise ScopeError(f"nmap exited {completed.returncode}")
    return parse_nmap_xml(completed.stdout)
