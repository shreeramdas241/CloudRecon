"""Render a self-contained HTML assessment report."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cloudrecon.lifecycle.store import Repository
from cloudrecon.util import project_root


def render_report(repo: Repository, scan_id: str | None = None) -> str:
    scans = repo.list_scans()
    selected = next((scan for scan in scans if scan.id == scan_id), scans[0] if scans else None)
    findings = repo.list_findings(limit=500)
    env = Environment(
        loader=FileSystemLoader(project_root() / "cloudrecon" / "reporting" / "templates"),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")
    demo = bool(selected and selected.demo) or any(item.demo for item in findings)
    return template.render(
        scan=selected,
        findings=findings,
        assets=repo.list_assets(),
        exposure=repo.list_exposure(),
        errors=repo.list_errors(selected.id if selected else None),
        metrics=repo.metrics(),
        demo=demo,
    )


def write_report(repo: Repository, destination: Path, scan_id: str | None = None) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_report(repo, scan_id), encoding="utf-8")
    return destination
