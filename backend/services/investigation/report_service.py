from datetime import datetime, timezone
from typing import Any


def generate_forensic_report(
    investigation: dict[str, Any],
    email_record: dict[str, Any],
) -> dict[str, Any]:
    email_data = email_record.get("email") or {}
    headers = email_data.get("headers") or {}
    risk_assessment = email_record.get("risk_assessment") or {}
    scoring_details = email_record.get("scoring_details") or {}
    subjective_logic = email_record.get("subjective_logic") or {}
    relay_analysis = email_record.get("relay_analysis") or {}
    evidence_list = email_record.get("evidence") or []
    campaign_correlation = email_record.get("campaign_correlation") or {}

    subject = headers.get("subject", "No Subject")
    senders = headers.get("sender") or []
    sender = senders[0] if senders else headers.get("from", "Unknown Sender")

    final_score = scoring_details.get("final_score", risk_assessment.get("score", 0))
    band = scoring_details.get("band", risk_assessment.get("category", "Low"))
    projected_prob = subjective_logic.get("projected_probability", 0.0)

    exec_summary = {
        "title": f"Forensic Threat Analysis: {subject}",
        "investigation_id": investigation.get("_id") or investigation.get("id"),
        "email_id": email_record.get("_id") or email_record.get("id"),
        "status": investigation.get("status", "open"),
        "priority": investigation.get("priority", "medium"),
        "subject": subject,
        "sender": sender,
        "message_id": headers.get("message_id"),
        "date": headers.get("date"),
        "overall_score": final_score,
        "threat_band": band,
        "threat_probability": projected_prob,
        "total_evidence_count": len(evidence_list),
        "primary_origin_ip": (relay_analysis.get("primary_origin") or {}).get("ip"),
        "campaign_id": campaign_correlation.get("campaign_id"),
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
    }

    evidence_ledger = []
    for ev in evidence_list:
        evidence_ledger.append({
            "evidence_id": ev.get("evidence_id"),
            "category": ev.get("category"),
            "type": ev.get("type"),
            "severity": ev.get("severity"),
            "direction": ev.get("direction"),
            "observation": ev.get("raw_observation"),
            "interpretation": ev.get("interpretation"),
            "conclusion": ev.get("conclusion"),
            "detection_method": ev.get("detection_method"),
            "reliability": ev.get("reliability"),
            "weight": ev.get("weight"),
            "contribution": ev.get("contribution"),
        })

    report = {
        "report_version": "1.0.0",
        "system": "S.H.I.E.L.D. Forensic Intelligence",
        "executive_summary": exec_summary,
        "scoring_model": {
            "formula": scoring_details.get("formula", "Standard heuristic"),
            "adversarial_score": scoring_details.get("raw_adversarial", 0.0),
            "legitimate_mitigation": scoring_details.get("raw_legitimate", 0.0),
            "uncertainty_penalty": scoring_details.get("uncertainty_penalty", 0.0),
            "final_score": final_score,
            "band": band,
        },
        "subjective_logic": {
            "belief": subjective_logic.get("belief", 0.0),
            "disbelief": subjective_logic.get("disbelief", 0.0),
            "uncertainty": subjective_logic.get("uncertainty", 1.0),
            "base_rate": subjective_logic.get("base_rate", 0.5),
            "projected_probability": projected_prob,
        },
        "transport_telemetry": {
            "total_hops": relay_analysis.get("total_hops", 0),
            "primary_origin": relay_analysis.get("primary_origin"),
            "origin_candidates": relay_analysis.get("origin_candidates", []),
            "anomalies": relay_analysis.get("anomalies", []),
        },
        "campaign_correlation": {
            "campaign_id": campaign_correlation.get("campaign_id"),
            "is_correlated": campaign_correlation.get("is_correlated", False),
            "confidence": campaign_correlation.get("confidence", 0.0),
            "related_email_ids": campaign_correlation.get("related_email_ids", []),
            "reasons": campaign_correlation.get("reasons", []),
        },
        "evidence_ledger": evidence_ledger,
        "investigation_notes": investigation.get("notes", []),
        "audit_trail": investigation.get("audit_log", []),
    }

    return report
