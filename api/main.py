"""Local FastAPI surface for the assessment database.

The API reads and labels data. It does not start a live AWS scan unless mode is
live and CLOUDRECON_ALLOW_LIVE_SCAN is true, and that path is still not the
default. Demo scans are rejected outside demo mode. Resolved cannot be set here.
"""

from __future__ import annotations

from pathlib import Path

from cloudrecon.config import Settings, load_settings
from cloudrecon.demo.runner import run_demo
from cloudrecon.errors import CloudReconError
from cloudrecon.lifecycle.store import Repository
from cloudrecon.reporting.export import findings_csv, findings_json
from cloudrecon.reporting.html_report import render_report
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field


class StatusUpdate(BaseModel):
    status: str = Field(min_length=2, max_length=40)
    note: str = Field(default="", max_length=1000)


def create_app(settings: Settings | None = None) -> FastAPI:
    current = settings or load_settings()
    app = FastAPI(title="CloudRecon", version="0.1.0", docs_url="/docs")
    app.state.settings = current

    @app.middleware("http")
    async def security_headers(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": current.mode}

    @app.get("/api/v1/metrics")
    def metrics() -> dict:
        return _repo(current).metrics()

    @app.get("/api/v1/assets")
    def assets() -> dict:
        return {"assets": _repo(current).list_assets(), "demo": current.mode == "demo"}

    @app.get("/api/v1/findings")
    def findings(
        severity: str | None = None,
        priority_band: str | None = None,
        remediation_status: str | None = None,
        match_status: str | None = None,
        region: str | None = None,
        kev: bool = False,
        q: str | None = Query(default=None, max_length=200),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict:
        rows = _repo(current).list_findings(
            severity=severity, priority_band=priority_band, remediation_status=remediation_status,
            match_status=match_status, region=region, kev=kev or None, q=q, limit=limit, offset=offset,
        )
        return {"findings": [row.model_dump() for row in rows]}

    @app.get("/api/v1/findings/export")
    def export_findings(fmt: str = Query(default="json", pattern="^(json|csv)$")) -> Response:
        rows = _repo(current).list_findings(limit=500)
        if fmt == "csv":
            return Response(findings_csv(rows), media_type="text/csv")
        return Response(findings_json(rows), media_type="application/json")

    @app.patch("/api/v1/findings/{finding_id}")
    def update_status(finding_id: str, body: StatusUpdate) -> dict[str, str]:
        try:
            _repo(current).set_remediation(finding_id, body.status, body.note)
        except CloudReconError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"id": finding_id, "status": body.status}

    @app.get("/api/v1/scans")
    def scans() -> dict:
        return {"scans": [scan.model_dump() for scan in _repo(current).list_scans()]}

    @app.get("/api/v1/exposure")
    def exposure() -> dict:
        return {"exposure": _repo(current).list_exposure()}

    @app.get("/api/v1/reports/latest", response_class=HTMLResponse)
    def latest_report() -> str:
        return render_report(_repo(current))

    @app.post("/api/v1/scans/demo")
    def demo_scan() -> dict:
        if current.mode != "demo":
            raise HTTPException(status_code=403, detail="Demo scans are disabled unless CLOUDRECON_MODE=demo")
        _reset_database(current.database)
        scan_id, stats = run_demo(current)
        return {"scan_id": scan_id, "stats": stats.as_dict(), "synthetic": True}

    return app


def _repo(settings: Settings) -> Repository:
    return Repository(settings.database)


def _reset_database(path: Path) -> None:
    if path.exists():
        path.unlink()


app = create_app()
