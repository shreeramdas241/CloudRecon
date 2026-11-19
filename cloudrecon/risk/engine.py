"""Configurable priority ranking.

The numeric result is a CloudRecon priority. The factor list is the explanation.
It is not represented as CVSS, EPSS, or an external standard.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from cloudrecon.models import (
    Asset,
    CorrelationResult,
    ExposureAssessment,
    MatchStatus,
    PrioritizedFinding,
    PriorityFactor,
)


class RiskRules(BaseModel):
    version: int = 1
    score_cap: float = 100
    cvss_multiplier: float = 4.0
    potential_match_multiplier: float = 0.7
    confirmed_match_multiplier: float = 1.0
    bands: dict[str, float] = Field(default_factory=lambda: {"critical": 80, "high": 55, "medium": 40, "low": 0})
    factors: dict[str, float] = Field(default_factory=dict)
    kev_minimum_band: str | None = "high"
    label: str = "CloudRecon priority"
    disclaimer: str = ""


def load_rules(path: Path) -> RiskRules:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return RiskRules.model_validate(payload)


def prioritize(
    finding: CorrelationResult,
    asset: Asset,
    exposure: ExposureAssessment | None,
    rules: RiskRules,
) -> PrioritizedFinding:
    factors: list[PriorityFactor] = []
    correlation = finding
    if correlation.cvss is not None:
        points = round(correlation.cvss * rules.cvss_multiplier, 2)
        factors.append(
            PriorityFactor(
                factor="cvss",
                points=points,
                detail=f"CVSS {correlation.cvss} x {rules.cvss_multiplier}",
            )
        )
    else:
        factors.append(
            PriorityFactor(factor="cvss", points=0, detail="CVSS score unavailable in the loaded intelligence")
        )
    if correlation.kev:
        factors.append(
            PriorityFactor(
                factor="kev",
                points=float(rules.factors.get("kev", 0)),
                detail="Listed in the loaded CISA KEV snapshot. No exploit was retrieved or tested.",
            )
        )
    if exposure is not None and exposure.verified_reachable:
        factors.append(
            PriorityFactor(
                factor="verified_exposure",
                points=float(rules.factors.get("verified_exposure", 0)),
                detail="An authorized probe verified at least one open port.",
            )
        )
    elif exposure is not None and exposure.internet_potential is True:
        factors.append(
            PriorityFactor(
                factor="potential_exposure",
                points=float(rules.factors.get("potential_exposure", 0)),
                detail="Potential internet exposure only. Reachability was not verified.",
            )
        )
    elif exposure is None or exposure.internet_potential is None:
        factors.append(
            PriorityFactor(
                factor="exposure_unknown",
                points=0,
                detail="Exposure data is incomplete, so no exposure points were added.",
            )
        )
    if asset.environment == "production":
        factors.append(
            PriorityFactor(
                factor="production_environment",
                points=float(rules.factors.get("production_environment", 0)),
                detail="Asset environment tag is production.",
            )
        )
    elif not asset.environment:
        factors.append(
            PriorityFactor(
                factor="environment_missing",
                points=0,
                detail="Environment tag is missing, so the production factor was not applied.",
            )
        )
    if asset.criticality == "high":
        factors.append(
            PriorityFactor(
                factor="criticality_high",
                points=float(rules.factors.get("criticality_high", 0)),
                detail="Asset criticality tag is high.",
            )
        )
    elif asset.criticality == "medium":
        factors.append(
            PriorityFactor(
                factor="criticality_medium",
                points=float(rules.factors.get("criticality_medium", 0)),
                detail="Asset criticality tag is medium.",
            )
        )
    if not correlation.fixed_version:
        factors.append(
            PriorityFactor(
                factor="fix_unavailable",
                points=float(rules.factors.get("fix_unavailable", 0)),
                detail="No fixed version was present in the matched intelligence.",
            )
        )
    else:
        factors.append(
            PriorityFactor(
                factor="fix_available",
                points=0,
                detail=f"A fixed version is recorded: {correlation.fixed_version}.",
            )
        )
    raw = round(sum(item.points for item in factors), 2)
    if correlation.status == MatchStatus.POTENTIAL:
        multiplier = rules.potential_match_multiplier
        match_detail = "Potential match multiplier applied because the version match is not confirmed."
    elif correlation.status == MatchStatus.CONFIRMED:
        multiplier = rules.confirmed_match_multiplier
        match_detail = "Confirmed match uses the configured confirmed multiplier."
    else:
        multiplier = 0
        match_detail = "Not affected or unknown matches are not prioritized as open risk."
    score = min(rules.score_cap, round(raw * multiplier, 2))
    factors.append(PriorityFactor(factor="match_confidence_multiplier", points=multiplier, detail=match_detail))
    band = _band(score, rules)
    if correlation.kev and rules.kev_minimum_band:
        band = _raise_band(band, rules.kev_minimum_band, rules)
        if band == rules.kev_minimum_band or _band_rank(band, rules) >= _band_rank(rules.kev_minimum_band, rules):
            factors.append(
                PriorityFactor(
                    factor="kev_minimum_band",
                    points=0,
                    detail=f"Configured rule keeps KEV findings at or above {rules.kev_minimum_band}.",
                )
            )
    return PrioritizedFinding(
        correlation=correlation,
        asset_id=asset.asset_id,
        priority_band=band,
        priority_score=score,
        priority_factors=factors,
        priority_disclaimer=rules.disclaimer,
    )


def _band(score: float, rules: RiskRules) -> str:
    ordered = sorted(rules.bands.items(), key=lambda item: item[1], reverse=True)
    for name, threshold in ordered:
        if score >= threshold:
            return name
    return "low"


def _band_rank(name: str, rules: RiskRules) -> float:
    return float(rules.bands.get(name, 0))


def _raise_band(current: str, minimum: str, rules: RiskRules) -> str:
    if _band_rank(current, rules) >= _band_rank(minimum, rules):
        return current
    return minimum
