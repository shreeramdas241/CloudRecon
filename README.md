# CloudRecon

CloudRecon is a local security assessment platform for **authorized** AWS EC2 inventory, read-only Linux discovery, CVE correlation, exposure review, and vulnerability lifecycle tracking.

It is built as a portfolio project. The demo runs entirely offline with synthetic instances. Live AWS calls are implemented and gated, and they were **not** executed against a real account in this workspace.

No license file is included yet. Do not treat the source as licensed for redistribution until one is added.

## What it does

- Inventories EC2 instances across explicit regions, including SSM status, security groups, routes, and load balancer relationships.
- Collects Ubuntu and Amazon Linux package, service, and process inventory through a static Bash script, preferably over SSM. Ansible can run the same script where SSH is already approved.
- Compares package versions with Debian, RPM, and PEP 440 rules, including distro revisions. A vendor or OSV range for the same release overrides a naive NVD upstream match, which is how backported fixes are represented.
- Enriches matches with a CISA KEV snapshot. It does not download exploit code.
- Separates **potential** internet exposure from **verified** reachability. A public IP or an open security group is not reported as confirmed exposure.
- Ranks findings with a configurable local priority and stores the factor list. That rank is not CVSS and not an industry-standard risk score.
- Tracks findings as open, under investigation, remediation in progress, resolved, accepted risk, or false positive. Resolved is set only after a successful rescan no longer sees the vulnerable version.
- Serves a FastAPI API, a Streamlit dashboard, CSV/JSON export, and an HTML report.

It does not patch systems, change infrastructure, exploit findings, or scan networks unless nmap is explicitly enabled and the target is on an allowlist. Nmap is off by default.

## Architecture

One Python process family, one SQLite file, and optional remote read-only commands. Details, the match order, and the lifecycle rules are in [docs/architecture.md](docs/architecture.md).

| Area | Module |
| --- | --- |
| EC2 inventory | `cloudrecon/discovery` |
| Host JSON | `scripts/collect_host.sh`, `ansible/playbooks/discover.yml` |
| CVE correlation | `cloudrecon/intel` |
| Exposure | `cloudrecon/exposure` |
| Priority | `cloudrecon/risk` and `config/risk_rules.yaml` |
| Storage and lifecycle | `cloudrecon/lifecycle` |
| API | `api/main.py` |
| Dashboard | `dashboard/app.py` |

## Demo data versus a live account

| Capability | Local demo and tests | Needs AWS credentials and an approved scope |
| --- | --- | --- |
| Synthetic fleet, findings, report, API, dashboard | Yes | No |
| Version matching, backport handling, priority, lifecycle | Yes | No |
| EC2 pagination, SSM command construction, Inspector and Trivy parsers | Tested with fixtures | Live clients are not invoked |
| `cloudrecon scan` | Refused | Yes |
| Nmap connect scan | Parser only | Only with both allow flags and an allowlist |
| NVD, OSV, full KEV refresh | Clients tested with mocks | Network and, for NVD, an API key for higher rate limits |

The demo account `111122223333` and instance IDs `i-0aaa000000000001` through `i-0aaa000000000006` are fictional. `CVE-9999-*` advisories are illustrative. `CVE-2021-44228` uses the published Log4j fixed version 2.15.0 and is still attached to a fictional instance. The KEV file is a partial excerpt. See [docs/limitations.md](docs/limitations.md).

## Install

Python 3.12 or newer. This workspace was exercised with Python 3.13.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m cloudrecon.cli check-config
python -m cloudrecon.cli demo --reset
```

`check-config` prints mode and scope. It does not call AWS and does not read access keys into the program configuration.

The demo writes:

- `data/cloudrecon.db` (gitignored)
- `examples/reports/demo-assessment.html`

Then:

```powershell
python -m cloudrecon.cli api
streamlit run dashboard/app.py
```

The API listens on `127.0.0.1:8000`. Interactive docs are at `/docs`. The dashboard is the Streamlit process, normally port 8501.

Docker Compose runs the same two processes and still does not call AWS. Seed the database with `docker compose run --rm api python -m cloudrecon.cli demo --reset` before opening the UI. See [docs/operations.md](docs/operations.md).

## Tests

```powershell
pytest
ruff check cloudrecon api dashboard tests
```

Tests use mocked AWS documents, local advisory snapshots, and the synthetic fleet. Do not read a passing test run as a live AWS verification.

## Live use

Live collection is documented in [docs/operations.md](docs/operations.md) and [docs/security.md](docs/security.md). It requires an explicit account and region scope, an instance tag, and `CLOUDRECON_ALLOW_LIVE_SCAN=true`. The example IAM policy is `examples/iam-policy.json`. It was not applied to an account here. Validate it before use.

Copy `.env.example` to `.env` only for local settings. Do not put AWS secret keys in it. boto3 uses the standard credential chain.

## Project layout

```text
ansible/          read-only discovery playbook
api/              FastAPI application
cloudrecon/       inventory, intel, risk, storage, CLI
config/           defaults, risk rules, example scope
dashboard/        Streamlit UI
database/         SQLite schema
docs/             architecture, operations, security, limitations
examples/         synthetic intel, IAM example, sample tool output
scripts/          Linux collector
tests/            offline automated tests
```

## Status

Implemented and covered by automated tests: inventory parsing, host JSON parsing, version comparison, vendor backport precedence, KEV enrichment, exposure classification, explainable priority, deduplication, rescan resolution, API validation, and failure recording.

Not verified here: any call to a real AWS account, SSM delivery to an instance, a live NVD/OSV/KEV refresh, Trivy or nmap execution, Jira delivery, or the Docker image build.
