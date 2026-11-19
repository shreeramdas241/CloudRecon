#!/usr/bin/env bash
# Read-only CloudRecon host inventory. Emits one JSON document on stdout.
# Do not pass untrusted arguments. The script does not evaluate a constructed command.
set -u
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/cloudrecon.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

run_to() {
  local dest="$1"
  shift
  if "$@" >"$dest" 2>"$dest.err"; then
    return 0
  fi
  return 1
}

run_to "$WORKDIR/os-release" cat /etc/os-release || true
run_to "$WORKDIR/uname" uname -r || true
run_to "$WORKDIR/ss" ss -lntuH || true
run_to "$WORKDIR/ps" ps -eo pid=,user=,comm=,args= || true
if command -v dpkg-query >/dev/null 2>&1; then
  echo deb >"$WORKDIR/manager"
  run_to "$WORKDIR/packages" dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\n' || echo dpkg-failed >"$WORKDIR/pkg-error"
elif command -v rpm >/dev/null 2>&1; then
  echo rpm >"$WORKDIR/manager"
  run_to "$WORKDIR/packages" rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' || echo rpm-failed >"$WORKDIR/pkg-error"
else
  echo unknown >"$WORKDIR/manager"
  echo no-package-manager >"$WORKDIR/pkg-error"
fi
if command -v docker >/dev/null 2>&1; then
  if run_to "$WORKDIR/docker" docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}'; then
    echo collected >"$WORKDIR/docker-status"
  else
    echo permission_denied >"$WORKDIR/docker-status"
  fi
else
  echo not_installed >"$WORKDIR/docker-status"
fi

if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' '{"schema_version":"1.0","collection_status":"failed","packages_complete":false,"errors":["python3 is not installed; inventory was not interpreted"],"packages":[],"services":[]}'
  exit 0
fi

python3 - "$WORKDIR" <<'PY'
import json, re, sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])

def text(name: str) -> str:
    path = root / name
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

def redact(value: str) -> str:
    value = re.sub(r"(?i)(password|secret|token|api[_-]?key)(\s*[:=]\s*)(\S+)", r"\1\2***", value)
    return re.sub(r"\bAKIA[0-9A-Z]{16}\b", "AKIA***REDACTED", value)

errors = []
os_values = {}
for line in text("os-release").splitlines():
    if "=" not in line:
        continue
    key, value = line.split("=", 1)
    os_values[key] = value.strip().strip('"')
kernel = text("uname").strip()
manager = text("manager").strip() or "unknown"
packages = []
pkg_error = (root / "pkg-error").exists()
if pkg_error:
    errors.append(text("pkg-error").strip() or f"{manager} package query failed")
else:
    for line in text("packages").splitlines():
        parts = line.split("\t")
        if manager == "deb" and len(parts) >= 2:
            packages.append({
                "name": parts[0], "version": parts[1], "epoch": "0",
                "arch": parts[2] if len(parts) > 2 else "", "manager": "deb", "release": "",
            })
        elif manager == "rpm" and len(parts) >= 4:
            epoch = parts[1] if parts[1] not in {"(none)", ""} else "0"
            packages.append({
                "name": parts[0], "epoch": epoch, "version": parts[2], "release": parts[3],
                "arch": parts[4] if len(parts) > 4 else "", "manager": "rpm",
            })
services = []
ss_error = (root / "ss.err").read_text(encoding="utf-8", errors="replace") if (root / "ss.err").exists() else ""
if ss_error.strip():
    errors.append("ss: " + redact(ss_error.strip())[:300])
for line in text("ss").splitlines():
    bits = line.split()
    if len(bits) < 5:
        continue
    local = bits[4] if bits[0].startswith("tcp") or bits[0].startswith("udp") else ""
    if not local:
        continue
    address, _, port = local.rpartition(":")
    if not port.isdigit():
        continue
    services.append({
        "name": "", "port": int(port), "protocol": "tcp" if bits[0].startswith("tcp") else "udp",
        "process": "", "pid": None, "executable": "", "address": address,
    })
processes = []
ps_lines = text("ps").splitlines()
for line in ps_lines[:200]:
    parts = line.split(None, 3)
    if len(parts) < 4 or not parts[0].isdigit():
        continue
    processes.append({
        "pid": int(parts[0]), "user": parts[1], "command": redact(parts[3]), "executable": parts[2],
    })
docker = []
docker_status = text("docker-status").strip() or "not_collected"
for line in text("docker").splitlines():
    parts = line.split("\t")
    if len(parts) >= 4:
        docker.append({"id": parts[0], "image": parts[1], "names": parts[2], "status": parts[3]})
status = "success"
packages_complete = not pkg_error and manager in {"deb", "rpm"}
if pkg_error or manager == "unknown":
    status = "failed" if not packages else "partial"
    packages_complete = False
if not text("os-release") and not packages:
    status = "failed"
    packages_complete = False
document = {
    "schema_version": "1.0",
    "collected_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "collection_status": status,
    "packages_complete": packages_complete,
    "errors": errors,
    "os": {
        "id": os_values.get("ID", ""),
        "version_id": os_values.get("VERSION_ID", ""),
        "pretty_name": os_values.get("PRETTY_NAME", ""),
        "kernel": kernel,
    },
    "packages": packages,
    "services": services,
    "processes": processes,
    "processes_truncated": len(ps_lines) > 200,
    "docker": docker,
    "docker_status": docker_status,
    "permissions_notes": [
        "Read-only commands only. Missing permissions are reported as errors, not as an empty vulnerability result."
    ],
}
print(json.dumps(document, separators=(",", ":")))
PY
