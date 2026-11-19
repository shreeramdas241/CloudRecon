"""Operator CLI. Live AWS calls stay behind explicit flags."""

from __future__ import annotations

import argparse
import sys

from cloudrecon.config import load_settings
from cloudrecon.demo.runner import run_demo
from cloudrecon.discovery.host import parse_host_document
from cloudrecon.errors import ScopeError
from cloudrecon.lifecycle.store import Repository
from cloudrecon.logging_utils import configure_logging
from cloudrecon.pipeline import AssessmentSource, run_assessment
from cloudrecon.reporting.html_report import write_report
from cloudrecon.scope import asset_in_scope, load_scope
from cloudrecon.util import isoformat, utcnow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cloudrecon", description="Authorized EC2 inventory and CVE correlation")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="Build a synthetic local assessment")
    demo.add_argument("--reset", action="store_true", help="Replace the demo database if it exists")
    demo.add_argument("--report", default="", help="HTML report output path")

    report = sub.add_parser("report", help="Render an HTML report from the current database")
    report.add_argument("--output", default="examples/reports/assessment.html")

    sub.add_parser("check-config", help="Print local configuration without calling AWS")
    sub.add_parser("api", help="Run the local API")

    schedule = sub.add_parser("schedule", help="Repeat the demo assessment locally")
    schedule.add_argument("--iterations", type=int, default=1)

    ingest = sub.add_parser("import-host", help="Correlate one collected host JSON file")
    ingest.add_argument("--asset-id", required=True)
    ingest.add_argument("--file", required=True)

    live = sub.add_parser("scan", help="Run a live read-only assessment")
    live.add_argument("--full", action="store_true", help="Mark assets missing from this inventory")

    args = parser.parse_args(argv)
    settings = load_settings()
    configure_logging(settings.log_level)
    if args.command == "demo":
        return _demo(settings, args.reset, args.report)
    if args.command == "report":
        path = write_report(Repository(settings.database), settings.path_for(args.output))
        print(path)
        return 0
    if args.command == "check-config":
        return _check(settings)
    if args.command == "api":
        import uvicorn

        uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=False)
        return 0
    if args.command == "schedule":
        from cloudrecon.automation.scheduler import ScanScheduler

        def _once() -> None:
            if settings.database.exists():
                settings.database.unlink()
            run_demo(settings)

        ScanScheduler(_once, interval_seconds=settings.scheduler_interval_seconds).run(args.iterations)
        return 0
    if args.command == "import-host":
        return _import_host(settings, args.asset_id, args.file)
    if args.command == "scan":
        return _live(settings, args.full)
    return 2


def _demo(settings, reset: bool, report: str) -> int:
    if settings.mode != "demo":
        print("Refusing demo because CLOUDRECON_MODE is not demo", file=sys.stderr)
        return 2
    if settings.database.exists() and not reset:
        print("Database exists. Re-run with --reset to rebuild the synthetic demo.", file=sys.stderr)
        return 2
    if settings.database.exists() and reset:
        settings.database.unlink()
    scan_id, stats = run_demo(settings)
    destination = settings.path_for(report or str(settings.path_for(settings.report_dir) / "demo-assessment.html"))
    write_report(Repository(settings.database), destination, scan_id)
    print(f"Synthetic scan {scan_id}")
    print(stats.as_dict())
    print(f"Report: {destination}")
    return 0


def _check(settings) -> int:
    print(f"mode={settings.mode}")
    print(f"database={settings.database}")
    print(f"intel_offline={settings.intel_offline}")
    print(f"allow_live_scan={settings.allow_live_scan}")
    print(f"allow_nmap={settings.allow_nmap}")
    print(f"enable_inspector={settings.enable_inspector}")
    print(f"enable_jira={settings.enable_jira}")
    print("aws_credentials=not read by check-config")
    try:
        scope = load_scope(settings.path_for(settings.scope_path))
        print(f"scope_accounts={','.join(scope.accounts)}")
        print(f"scope_regions={','.join(scope.regions)}")
    except ScopeError as exc:
        print(f"scope_error={exc}")
    return 0


def _import_host(settings, asset_id: str, file_name: str) -> int:
    repo = Repository(settings.database)
    asset = repo.get_asset(asset_id)
    if asset is None:
        print("Asset is not in the local inventory. Discover it before importing host data.", file=sys.stderr)
        return 2
    document = parse_host_document(settings.path_for(file_name).read_text(encoding="utf-8"))
    _scan, stats = run_assessment(
        settings,
        AssessmentSource(mode=settings.mode, assets=[asset], hosts={asset.asset_id: document}),
        now=utcnow(),
        demo=settings.mode == "demo",
    )
    print(stats.as_dict())
    return 0


def _live(settings, full: bool) -> int:
    if not settings.live_enabled:
        print("Live scan refused. Set CLOUDRECON_MODE=live and CLOUDRECON_ALLOW_LIVE_SCAN=true.", file=sys.stderr)
        return 2
    scope = load_scope(settings.path_for(settings.scope_path))
    from cloudrecon.discovery.aws_boto import BotoInventoryBackend
    from cloudrecon.discovery.ec2 import discover
    from cloudrecon.discovery.ssm import SsmCollector
    from cloudrecon.models import HostInventory

    backend = BotoInventoryBackend()
    bundle = discover(backend, scope.regions)
    selected = []
    skipped = 0
    for asset in bundle.assets:
        if asset_in_scope(asset, scope):
            selected.append(asset)
        else:
            skipped += 1
    hosts: dict[str, HostInventory | None] = {}
    collector = SsmCollector(backend.session())
    for asset in selected:
        if not asset.ssm_managed:
            hosts[asset.asset_id] = None
            continue
        try:
            hosts[asset.asset_id] = collector.collect(asset.instance_id, asset.region)
        except Exception as exc:
            hosts[asset.asset_id] = HostInventory(
                collected_at=isoformat(),
                collection_status="failed",
                packages_complete=False,
                errors=[f"SSM collection failed: {exc}"],
            )
    source = AssessmentSource(mode="live", assets=selected, hosts=hosts, errors=bundle.errors)
    scan_id, stats = run_assessment(settings, source, demo=False, full_reconcile=full)
    stats.out_of_scope += skipped
    print(f"Live scan {scan_id}")
    print(stats.as_dict())
    print("AWS write actions were not used. Remediation was not applied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
