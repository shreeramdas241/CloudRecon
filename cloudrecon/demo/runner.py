"""Run the two-scan synthetic assessment."""

from __future__ import annotations

from cloudrecon.config import Settings
from cloudrecon.demo.fixtures import demo_assets, hosts_after, hosts_before
from cloudrecon.pipeline import AssessmentSource, ScanStats, run_assessment
from cloudrecon.util import shift, utcnow


def run_demo(settings: Settings) -> tuple[str, ScanStats]:
    if settings.mode != "demo":
        raise SystemExit("The demo command runs only when CLOUDRECON_MODE=demo")
    assets = demo_assets()
    moment = utcnow()
    earlier = shift(moment, days=-14)
    run_assessment(
        settings,
        AssessmentSource(mode="demo", assets=assets, hosts=hosts_before(earlier.isoformat())),
        now=earlier,
        demo=True,
    )
    return run_assessment(
        settings,
        AssessmentSource(mode="demo", assets=assets, hosts=hosts_after(moment.isoformat())),
        now=moment,
        demo=True,
    )
