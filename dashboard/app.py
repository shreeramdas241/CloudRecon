"""Local CloudRecon dashboard. It reads the assessment database and does not scan AWS."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import streamlit as st
from cloudrecon.config import load_settings
from cloudrecon.lifecycle.store import Repository
from cloudrecon.reporting.export import findings_csv, findings_json

st.set_page_config(page_title="CloudRecon", layout="wide")
st.markdown(
    """
    <style>
    .block-container { padding-top: 1.2rem; }
    .demo-banner { background: #fff6e8; border: 1px solid #e2b15a; padding: 0.7rem 0.9rem; border-radius: 6px; }
    </style>
    """,
    unsafe_allow_html=True,
)

settings = load_settings()
st.title("CloudRecon")
st.caption("Authorized EC2 inventory, exposure context, and CVE correlation. Priority is a local ranking, not CVSS.")

if not settings.database.exists():
    st.info("No database yet. From the repository root run: python -m cloudrecon.cli demo --reset")
    st.stop()

repo = Repository(settings.database)
metrics = repo.metrics()
if settings.mode == "demo":
    st.markdown(
        '<div class="demo-banner">Demo mode. Figures below come from the local synthetic assessment, '
        "not a live AWS account. CVE-9999-* rows are illustrative. Open KEV rows use the published "
        "CVE-2021-44228 range on a fictional instance.</div>",
        unsafe_allow_html=True,
    )

assets = repo.list_assets()
exposure = repo.list_exposure()
scans = repo.list_scans()

left, middle, right = st.columns(3)
left.metric("EC2 instances", metrics["assets"])
middle.metric("Fully scanned", metrics["scanned_assets"])
right.metric("Not fully scanned", metrics["unscanned_assets"])
c1, c2, c3, c4 = st.columns(4)
c1.metric("Open critical", metrics["open_by_severity"].get("CRITICAL", 0))
c2.metric("Open high", metrics["open_by_severity"].get("HIGH", 0))
c3.metric("Open KEV", metrics["open_kev"])
c4.metric("Potential internet exposure", metrics["potential_internet_exposed"])

tab_overview, tab_findings, tab_assets, tab_exposure, tab_scans = st.tabs(
    ["Overview", "Findings", "Assets", "Exposure", "Scans"]
)

with tab_overview:
    st.subheader("Open findings by severity")
    severity = metrics["open_by_severity"] or {"none": 0}
    st.bar_chart(pd.DataFrame({"findings": severity}))
    region_counts = metrics["open_by_region"] or {"none": 0}
    st.subheader("Open findings by region")
    st.bar_chart(pd.DataFrame({"findings": region_counts}))
    st.subheader("Remediation")
    remediation = [{"status": key, "count": value} for key, value in metrics["remediation"].items()]
    st.dataframe(pd.DataFrame(remediation), hide_index=True)
    st.subheader("Trend")
    if metrics["trend"]:
        trend = pd.DataFrame(metrics["trend"])
        st.line_chart(trend.pivot(index="day", columns="event_type", values="n").fillna(0))
    else:
        st.caption("No finding events yet.")
    st.subheader("Highest local priority assets")
    st.dataframe(pd.DataFrame(metrics["most_vulnerable_assets"]), hide_index=True, use_container_width=True)

with tab_findings:
    st.caption("Confirmed affected is an ecosystem version match. Potentially affected still needs corroboration.")
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    bands = ["critical", "high", "medium", "low"]
    statuses = ["open", "under_investigation", "remediation_in_progress", "resolved", "accepted_risk", "false_positive"]
    matches = ["confirmed_affected", "potentially_affected"]
    regions = sorted({row["region"] for row in assets})
    f1, f2, f3, f4 = st.columns(4)
    severity_filter = f1.multiselect("Severity", severities)
    band_filter = f2.multiselect("Priority", bands)
    status_filter = f3.multiselect("Remediation", statuses, default=["open"])
    match_filter = f4.multiselect("Match", matches)
    region_filter = st.multiselect("Region", regions)
    kev_only = st.checkbox("CISA KEV only")
    query = st.text_input("Search CVE, package, or asset", max_chars=200)
    selected_status = status_filter[0] if len(status_filter) == 1 else None
    selected_severity = severity_filter[0] if len(severity_filter) == 1 else None
    selected_band = band_filter[0] if len(band_filter) == 1 else None
    selected_match = match_filter[0] if len(match_filter) == 1 else None
    selected_region = region_filter[0] if len(region_filter) == 1 else None
    rows = repo.list_findings(
        severity=selected_severity,
        priority_band=selected_band,
        remediation_status=selected_status,
        match_status=selected_match,
        region=selected_region,
        kev=True if kev_only else None,
        q=query or None,
        limit=500,
    )
    multi = any(
        len(selected) > 1
        for selected in (status_filter, severity_filter, band_filter, match_filter, region_filter)
    )
    if multi:
        rows = [
            row for row in rows
            if (not status_filter or row.remediation_status in status_filter)
            and (not severity_filter or row.severity in severity_filter)
            and (not band_filter or row.priority_band in band_filter)
            and (not match_filter or row.match_status in match_filter)
            and (not region_filter or row.region in region_filter)
        ]
    frame = pd.DataFrame([row.model_dump() for row in rows])
    if frame.empty:
        st.warning("No findings match these filters.")
    else:
        st.dataframe(
            frame[[
                "cve_id", "asset_name", "region", "package_name", "installed_version", "fixed_version",
                "match_status", "cvss", "severity", "kev", "priority_band", "priority_score",
                "remediation_status", "illustrative",
            ]],
            hide_index=True,
            use_container_width=True,
        )
        st.download_button("Download CSV", findings_csv(rows), file_name="cloudrecon-findings.csv")
        st.download_button("Download JSON", findings_json(rows), file_name="cloudrecon-findings.json")
        labels = [f"{row.cve_id} · {row.asset_name or row.asset_id} · {row.package_name}" for row in rows]
        choice = st.selectbox("Evidence", labels)
        chosen = rows[labels.index(choice)]
        st.write(
            f"**{chosen.match_status}** · confidence {chosen.confidence} · "
            f"priority {chosen.priority_band} ({chosen.priority_score})"
        )
        st.caption(chosen.priority_disclaimer)
        st.dataframe(pd.DataFrame(chosen.priority_explanation), hide_index=True, use_container_width=True)
        st.dataframe(pd.DataFrame(chosen.evidence), hide_index=True, use_container_width=True)

with tab_assets:
    st.dataframe(pd.DataFrame(assets), hide_index=True, use_container_width=True)
    st.caption("ssm_managed null means the SSM API result was unavailable. That is not the same as unmanaged.")

with tab_exposure:
    st.caption("Potential exposure is not verified reachability. Unknown means the AWS data was incomplete.")
    st.dataframe(pd.DataFrame(exposure), hide_index=True, use_container_width=True)

with tab_scans:
    st.dataframe(pd.DataFrame([scan.model_dump() for scan in scans]), hide_index=True, use_container_width=True)
    st.subheader("Collection errors")
    st.dataframe(pd.DataFrame(repo.list_errors()), hide_index=True, use_container_width=True)
    st.caption("Failed collection does not clear existing findings.")
