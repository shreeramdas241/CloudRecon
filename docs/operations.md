# Operations

## Local demo

From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m cloudrecon.cli check-config
python -m cloudrecon.cli demo --reset
pytest
ruff check cloudrecon api dashboard tests
python -m cloudrecon.cli api
streamlit run dashboard/app.py
```

On a POSIX shell, activate `.venv/bin/activate` instead. `demo --reset` rebuilds `data/cloudrecon.db` and writes `examples/reports/demo-assessment.html`. Both are labeled synthetic.

The API is at `http://127.0.0.1:8000` and the interactive docs are at `/docs`. The dashboard reads the same database.

## What runs without AWS

Demo mode, unit tests, report rendering, the API, the dashboard, host JSON import, Trivy JSON import through the correlator, and the Nmap XML parser. Nmap itself is not invoked by the tests.

## What needs an authorized account

`python -m cloudrecon.cli scan` after:

1. Copy `config/scope.example.yaml` to a scope file and replace the account ID and regions.
2. Tag the instances that may be collected with `CloudRecon=authorized`.
3. Attach a role based on `examples/iam-policy.json`. See `docs/security.md` for the permission notes.
4. Set `CLOUDRECON_MODE=live` and `CLOUDRECON_ALLOW_LIVE_SCAN=true`.
5. Leave `CLOUDRECON_ALLOW_NMAP=false` unless a specific allowlist has been approved.

The scan is read-only aside from `ssm:SendCommand` of the static collector. It does not patch instances. Hosts that are not SSM-managed are inventoried from AWS APIs and left unscanned. Use Ansible only where SSH has already been approved:

```bash
ansible-galaxy collection install -r ansible/collections/requirements.yml
ansible-playbook -i ansible/inventory/example.ini ansible/playbooks/discover.yml
python -m cloudrecon.cli import-host --asset-id ACCOUNT/REGION/INSTANCE --file examples/hosts/HOSTNAME.json
```

Import correlates a file for an asset that is already in the database. It does not open an SSH session.

## Optional integrations

Jira and webhooks stay disabled until `CLOUDRECON_ENABLE_JIRA` or `CLOUDRECON_WEBHOOK_URL` is set. Inspector findings are parsed from JSON and, when `CLOUDRECON_ENABLE_INSPECTOR=true`, listed with the injected boto3 client during a live scan. None of these are required for the demo.

Refresh intelligence by replacing the JSON snapshots or by calling the NVD, OSV, and KEV clients with `CLOUDRECON_INTEL_OFFLINE=false` in a live workflow. Offline mode is the default so tests and demos do not depend on external services.

## Scheduling

`python -m cloudrecon.cli schedule --iterations 1` repeats the synthetic demo. For a real account, run `cloudrecon scan` from an approved scheduler with the role above. The GitHub workflow `scheduled-demo.yml` runs the synthetic assessment only and uploads the HTML report. It does not use AWS credentials.

## Failure behavior

Region access errors are stored on the scan and the other regions continue. HTTP 429 and 5xx responses retry with backoff. A failed host collection is visible in the dashboard and does not clear findings. A failed assessment marks the scan `failed` and can notify a configured webhook.
