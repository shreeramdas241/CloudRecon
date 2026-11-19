# Security considerations

CloudRecon is an assessment tool for accounts and hosts the operator is allowed to read. It does not exploit vulnerabilities, escalate privileges, persist on a host, or hide its commands.

## Authorization boundary

Live mode does nothing unless both `CLOUDRECON_MODE=live` and `CLOUDRECON_ALLOW_LIVE_SCAN=true` are set. It then refuses to run without `config/scope.yaml` listing account IDs and regions. Instances must also carry the configured tag, `CloudRecon=authorized` in the example. Instances outside that scope are counted and not collected.

Nmap is off unless the process flag and the scope flag are both true and the target is on the scope allowlist. The command is a TCP connect scan of an explicit port list, built as an argument vector with `shell=False`. Probe results submitted without that authorization are ignored and cannot mark a path as verified.

Demo mode cannot be used to flip a live database into a synthetic reset. The demo command exits when the mode is not `demo`. The demo API route returns 403 in any other mode.

## Credentials

AWS credentials are not parameters of this project. boto3 uses the standard credential chain. `check-config` does not call AWS and does not print credentials. Do not put keys in `.env`. `.env.example` documents empty integration settings only.

Logs and host command lines pass through redaction for common secret assignments and AKIA-style access key IDs. Redaction is a backstop, not a reason to collect secrets. The collector does not read environment files or cloud credentials on the instance.

## Host collection

The Bash script is static. SSM sends that file as the command body. Instance IDs are checked against `i-` plus 8 to 17 hex characters before they are placed in an API call. The script does not `eval` input. It uses `dpkg-query`, `rpm`, `ss`, `ps`, and optional `docker ps`. Failures are recorded. A permission error is not stored as "no packages" with a successful status, and it does not resolve older findings.

Ansible runs the same script with `become: false`. SSH is optional and not the default. Prefer SSM.

## IAM

`examples/iam-policy.json` is a starting point. It allows identity lookup, EC2 and load balancer reads, SSM status reads, `ssm:SendCommand` for `AWS-RunShellScript`, and optional `inspector2:ListFindings`.

`SendCommand` is split so the instance resource can require `ssm:resourceTag/CloudRecon=authorized` while the document resource is named explicitly. Describe APIs in this policy are not resource-constrained because those EC2 read actions generally do not support resource-level permissions. This policy was not executed against a live account in this workspace. Validate it with IAM Access Analyzer and a test role before use. Do not add start, stop, or session privileges for the assessment role.

## What this tool will not do

It will not patch, reboot, or change security groups. Jira and webhook notifications are optional and create a ticket or a message only. There is no exploit repository and no payload generation. KEV is used as a catalog flag with the statement that exploit code is not retrieved.

## Data handling

The SQLite file and `.env` are gitignored. Reports can still contain host package inventories and IP addresses. Treat `data/` and generated reports as sensitive even when the demo banner is present. The demo report is synthetic and labeled.
