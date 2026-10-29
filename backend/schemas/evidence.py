from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

EvidenceSeverity = Literal["informational", "low", "medium", "high", "critical"]
EvidenceDirection = Literal["malicious", "legitimate", "inconclusive"]
DetectionMethod = Literal["deterministic", "heuristic", "cryptographic", "dns_lookup"]
EvidenceCategory = Literal["authentication", "headers", "urls", "attachments", "relay", "content"]


class EvidenceObject(BaseModel):
    evidence_id: str
    investigation_id: str | None = None
    type: str
    category: EvidenceCategory
    raw_observation: str
    interpretation: str
    conclusion: str
    source_component: str
    source_reference: str | None = None
    detection_method: DetectionMethod
    observed_at: datetime | str
    severity: EvidenceSeverity
    direction: EvidenceDirection
    reliability: float = Field(ge=0.0, le=1.0)
    weight: float = Field(default=1.0, ge=0.0, le=10.0)
    is_verified: bool = False
    uncertainty: float = Field(default=0.0, ge=0.0, le=1.0)
    contribution: float = 0.0


class SubjectiveLogicOpinion(BaseModel):
    belief: float = Field(ge=0.0, le=1.0)
    disbelief: float = Field(ge=0.0, le=1.0)
    uncertainty: float = Field(ge=0.0, le=1.0)
    base_rate: float = Field(default=0.5, ge=0.0, le=1.0)
    projected_probability: float = Field(ge=0.0, le=1.0)


class ScoringBreakdown(BaseModel):
    formula: str
    raw_adversarial: float
    raw_legitimate: float
    net_score: float
    uncertainty_penalty: float
    final_score: int
    band: str
    contributions: list[dict]


class ForensicAnalysisBundle(BaseModel):
    evidence: list[EvidenceObject]
    scoring: ScoringBreakdown
    opinion: SubjectiveLogicOpinion
