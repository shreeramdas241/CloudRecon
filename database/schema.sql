PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    name TEXT,
    instance_type TEXT,
    state TEXT,
    private_ip TEXT,
    public_ip TEXT,
    ami_id TEXT,
    vpc_id TEXT,
    subnet_id TEXT,
    iam_profile TEXT,
    ssm_managed INTEGER,
    ssm_ping_status TEXT,
    launch_time TEXT,
    environment TEXT,
    criticality TEXT,
    security_groups_json TEXT NOT NULL DEFAULT '[]',
    tags_json TEXT NOT NULL DEFAULT '{}',
    has_igw_route INTEGER,
    load_balancers_json TEXT NOT NULL DEFAULT '[]',
    sg_collected INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    scope TEXT,
    stats_json TEXT NOT NULL DEFAULT '{}',
    error TEXT,
    demo INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    asset_id TEXT,
    stage TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS snapshots (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    collection_status TEXT NOT NULL,
    packages_complete INTEGER NOT NULL,
    os_json TEXT NOT NULL DEFAULT '{}',
    errors_json TEXT NOT NULL DEFAULT '[]',
    docker_status TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    release TEXT,
    epoch TEXT,
    arch TEXT,
    manager TEXT NOT NULL,
    source TEXT,
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id TEXT NOT NULL,
    name TEXT NOT NULL,
    port INTEGER,
    protocol TEXT,
    process TEXT,
    pid INTEGER,
    executable TEXT,
    address TEXT,
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    asset_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    affected_versions TEXT,
    fixed_version TEXT,
    advisory_sources TEXT NOT NULL DEFAULT '[]',
    cvss REAL,
    severity TEXT,
    kev INTEGER NOT NULL DEFAULT 0,
    kev_json TEXT NOT NULL DEFAULT '{}',
    match_status TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    priority_band TEXT,
    priority_score REAL,
    priority_explanation TEXT NOT NULL DEFAULT '[]',
    priority_disclaimer TEXT,
    remediation_status TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    last_scan_id TEXT,
    status_note TEXT,
    demo INTEGER NOT NULL DEFAULT 0,
    illustrative INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE TABLE IF NOT EXISTS finding_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    scan_id TEXT,
    event_type TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS exposure (
    asset_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    internet_potential INTEGER,
    verified_reachable INTEGER NOT NULL DEFAULT 0,
    sg_open_to_world INTEGER,
    summary TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    assessed_at TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

CREATE TABLE IF NOT EXISTS http_cache (
    cache_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    stored_at TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(remediation_status);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_asset ON snapshots(asset_id);
CREATE INDEX IF NOT EXISTS idx_events_finding ON finding_events(finding_id);
