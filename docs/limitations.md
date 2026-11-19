# Limitations

These limits are part of the design, not unfinished placeholders.

- Live AWS, SSM, Inspector, NVD, OSV, and CISA calls were not executed in this workspace. The boto3 and HTTP clients are implemented and covered with fake clients or recorded documents. A successful demo run is not evidence that an account integration works.
- The offline intelligence files are a curated subset. `CVE-9999-*` identifiers and their ranges are illustrative. `CVE-2021-44228` uses the published fixed version 2.15.0 and is attached to a fictional instance. The KEV file is a partial excerpt, not the full catalog. Operational use needs a refresh from NVD, OSV or the distro advisory feed, and the full CISA KEV JSON.
- Vendor matching requires an advisory for the same ecosystem string, such as `Ubuntu:22.04`. A different release is not treated as confirmed. NVD can still produce a potential match on the upstream version.
- Kernel and userspace backports are handled only when the advisory range is in the package manager's version format. The engine does not ship a complete Ubuntu USN or ALAS corpus.
- Exposure is inferred from collected API data. It is not a reachability proof. Prefix lists and referenced security groups are unknown unless their contents were expanded. Load balancer mapping depends on ELBv2 target health and does not cover every classic load balancer or NLB target type.
- Nmap, when explicitly enabled, is a connect scan from the operator host. It does not prove the path an internet client would use, and it is off by default.
- Trivy and Inspector are importers. Demo mode does not run either product.
- Package collection supports Debian/Ubuntu and RPM families first. Other operating systems return an unsupported manager and are not force-matched.
- Resolved status means a later successful inventory no longer contains that package version. It does not mean the asset was exploited, and it does not mean a human accepted the risk.
- CloudRecon priority is a weighted local rank. It is not CVSS, EPSS, or a vendor risk score. Weights live in `config/risk_rules.yaml` so they can be changed and explained.
- The scheduler in the CLI repeats the local demo assessment. It is not a multi-tenant job system. Notifications are best-effort and do not retry forever.
- SQLite is the storage engine. It is appropriate for a single operator. It is not a concurrent multi-writer service.
