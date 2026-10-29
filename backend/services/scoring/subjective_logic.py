from dataclasses import dataclass
from typing import Sequence

from schemas.evidence import EvidenceObject, SubjectiveLogicOpinion


@dataclass
class Opinion:
    belief: float
    disbelief: float
    uncertainty: float
    base_rate: float = 0.5

    def __post_init__(self):
        total = self.belief + self.disbelief + self.uncertainty
        if total > 0 and abs(total - 1.0) > 1e-5:
            self.belief = round(self.belief / total, 6)
            self.disbelief = round(self.disbelief / total, 6)
            self.uncertainty = round(max(0.0, 1.0 - (self.belief + self.disbelief)), 6)

    @property
    def projected_probability(self) -> float:
        return min(1.0, max(0.0, self.belief + self.base_rate * self.uncertainty))

    def to_schema(self) -> SubjectiveLogicOpinion:
        return SubjectiveLogicOpinion(
            belief=round(self.belief, 4),
            disbelief=round(self.disbelief, 4),
            uncertainty=round(self.uncertainty, 4),
            base_rate=round(self.base_rate, 4),
            projected_probability=round(self.projected_probability, 4),
        )


def evidence_to_opinion(ev: EvidenceObject) -> Opinion:
    sev_mult = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.50,
        "low": 0.25,
        "informational": 0.05,
    }.get(ev.severity, 0.1)

    weight_scale = min(1.0, max(0.2, ev.weight / 3.0))
    strength = sev_mult * ev.reliability * weight_scale
    effective_uncertainty = max(0.05, min(0.95, ev.uncertainty))

    if ev.direction == "malicious":
        b = min(0.95, strength * (1.0 - effective_uncertainty))
        d = 0.0
        u = max(0.05, 1.0 - b)
    elif ev.direction == "legitimate":
        b = 0.0
        d = min(0.95, strength * (1.0 - effective_uncertainty))
        u = max(0.05, 1.0 - d)
    else:
        b = 0.0
        d = 0.0
        u = 1.0

    return Opinion(belief=b, disbelief=d, uncertainty=u, base_rate=0.5)


def fuse_consensus(op_a: Opinion, op_b: Opinion) -> Opinion:
    kappa = op_a.uncertainty + op_b.uncertainty - (op_a.uncertainty * op_b.uncertainty)

    if kappa > 1e-6:
        b = (op_a.belief * op_b.uncertainty + op_b.belief * op_a.uncertainty) / kappa
        d = (op_a.disbelief * op_b.uncertainty + op_b.disbelief * op_a.uncertainty) / kappa
        u = (op_a.uncertainty * op_b.uncertainty) / kappa
        denom_a = op_a.uncertainty + op_b.uncertainty
        base_rate = (
            (op_a.base_rate * op_b.uncertainty + op_b.base_rate * op_a.uncertainty) / denom_a
            if denom_a > 1e-6 else 0.5
        )
    else:
        b = (op_a.belief + op_b.belief) / 2.0
        d = (op_a.disbelief + op_b.disbelief) / 2.0
        u = 0.0
        base_rate = 0.5

    return Opinion(belief=b, disbelief=d, uncertainty=u, base_rate=base_rate)


def fuse_averaging(op_a: Opinion, op_b: Opinion) -> Opinion:
    b = (op_a.belief + op_b.belief) / 2.0
    d = (op_a.disbelief + op_b.disbelief) / 2.0
    u = (op_a.uncertainty + op_b.uncertainty) / 2.0
    base_rate = (op_a.base_rate + op_b.base_rate) / 2.0
    return Opinion(belief=b, disbelief=d, uncertainty=u, base_rate=base_rate)


def evaluate_subjective_logic(evidence_list: Sequence[EvidenceObject]) -> SubjectiveLogicOpinion:
    if not evidence_list:
        return Opinion(belief=0.0, disbelief=0.0, uncertainty=1.0, base_rate=0.5).to_schema()

    # Category grouping
    categories: dict[str, list[Opinion]] = {}
    for ev in evidence_list:
        op = evidence_to_opinion(ev)
        categories.setdefault(ev.category, []).append(op)

    category_opinions: list[Opinion] = []
    for cat_name, ops in categories.items():
        if not ops:
            continue
        accum = ops[0]
        for next_op in ops[1:]:
            accum = fuse_consensus(accum, next_op)
        category_opinions.append(accum)

    if not category_opinions:
        return Opinion(belief=0.0, disbelief=0.0, uncertainty=1.0, base_rate=0.5).to_schema()

    final_opinion = category_opinions[0]
    for next_cat in category_opinions[1:]:
        final_opinion = fuse_consensus(final_opinion, next_cat)

    return final_opinion.to_schema()
