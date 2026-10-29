import math
from typing import Any

from schemas.evidence import EvidenceObject, ScoringBreakdown

SEVERITY_MULTIPLIERS = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
    "informational": 0.05,
}


def calculate_formula_score(evidence_list: list[EvidenceObject]) -> ScoringBreakdown:
    detailed_contributions: list[dict[str, Any]] = []

    c_malicious = 0.0
    c_legitimate = 0.0
    c_inconclusive = 0.0
    has_critical_malicious = False

    for ev in evidence_list:
        s_mult = SEVERITY_MULTIPLIERS.get(ev.severity, 0.1)
        contribution = round(ev.weight * s_mult * ev.reliability, 4)
        ev.contribution = contribution

        item = {
            "evidence_id": ev.evidence_id,
            "type": ev.type,
            "category": ev.category,
            "severity": ev.severity,
            "direction": ev.direction,
            "weight": ev.weight,
            "severity_multiplier": s_mult,
            "reliability": ev.reliability,
            "contribution": contribution,
            "raw_observation": ev.raw_observation,
        }
        detailed_contributions.append(item)

        if ev.direction == "malicious":
            c_malicious += contribution
            if ev.severity == "critical":
                has_critical_malicious = True
        elif ev.direction == "legitimate":
            c_legitimate += contribution
        else:
            c_inconclusive += contribution

    # Exponential saturation mapping
    if c_malicious > 0:
        scaled_malicious = 100.0 * (1.0 - math.exp(-c_malicious / 3.5))
    else:
        scaled_malicious = 0.0

    # Legitimate mitigation is suppressed when critical threat indicators exist
    mitigation_factor = 0.0 if has_critical_malicious else min(25.0, c_legitimate * 6.0)
    uncertainty_penalty = min(15.0, c_inconclusive * 2.0)

    net_score = max(0.0, scaled_malicious - mitigation_factor + uncertainty_penalty)
    final_score = int(round(min(100.0, max(0.0, net_score))))

    if final_score >= 80:
        band = "Critical"
    elif final_score >= 60:
        band = "High"
    elif final_score >= 40:
        band = "Elevated"
    elif final_score >= 20:
        band = "Guarded"
    else:
        band = "Low"

    formula_desc = "Score = clamp(0, 100, round(100 * (1 - exp(-C_malicious / 3.5)) - Mitigation + UncertaintyPenalty))"

    return ScoringBreakdown(
        formula=formula_desc,
        raw_adversarial=round(c_malicious, 4),
        raw_legitimate=round(c_legitimate, 4),
        net_score=round(net_score, 2),
        uncertainty_penalty=round(uncertainty_penalty, 2),
        final_score=final_score,
        band=band,
        contributions=detailed_contributions,
    )
