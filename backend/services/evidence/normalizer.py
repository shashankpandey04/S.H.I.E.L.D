from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from schemas.evidence import EvidenceObject

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".hta", ".iso", ".wsf",
    ".ps1", ".jar", ".com", ".pif", ".docm", ".xlsm", ".pptm"
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}


def generate_evidence_id(category: str, ev_type: str, raw_observation: str) -> str:
    digest = sha256(f"{category}:{ev_type}:{raw_observation}".encode("utf-8")).hexdigest()[:12]
    return f"ev_{digest}"


def normalize_forensic_evidence(
    parsed_email: dict[str, Any],
    authentication: dict[str, Any],
    url_analysis: dict[str, Any],
    header_analysis: dict[str, Any],
    relay_analysis: dict[str, Any],
    investigation_id: str | None = None,
) -> list[EvidenceObject]:
    evidence: list[EvidenceObject] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Authentication Evidence
    reported_parsed = (authentication.get("reported_results") or {}).get("parsed") or {}
    spf_res = (reported_parsed.get("spf") or {}).get("result")
    dkim_res = (reported_parsed.get("dkim") or {}).get("result")
    dmarc_res = (reported_parsed.get("dmarc") or {}).get("result")

    if dkim_res == "pass":
        ev_type = "auth.dkim.reported_pass"
        obs = "Receiving mail server verified DKIM signature successfully."
        evidence.append(EvidenceObject(
            evidence_id=generate_evidence_id("authentication", ev_type, obs),
            investigation_id=investigation_id,
            type=ev_type,
            category="authentication",
            raw_observation=obs,
            interpretation="Email content integrity and sender domain authenticity were verified by receiving server.",
            conclusion="Positive cryptographic integrity indicator.",
            source_component="authentication_verifier",
            source_reference="Authentication-Results",
            detection_method="deterministic",
            observed_at=now_iso,
            severity="informational",
            direction="legitimate",
            reliability=0.85,
            weight=1.5,
            is_verified=True,
            uncertainty=0.10,
        ))
    elif dkim_res == "fail":
        ev_type = "auth.dkim.reported_fail"
        obs = "Receiving mail server reported DKIM signature verification failure."
        evidence.append(EvidenceObject(
            evidence_id=generate_evidence_id("authentication", ev_type, obs),
            investigation_id=investigation_id,
            type=ev_type,
            category="authentication",
            raw_observation=obs,
            interpretation="Cryptographic signature mismatch indicates message was altered in transit or forged.",
            conclusion="Possible message tampering or domain spoofing.",
            source_component="authentication_verifier",
            source_reference="Authentication-Results",
            detection_method="deterministic",
            observed_at=now_iso,
            severity="medium",
            direction="malicious",
            reliability=0.80,
            weight=2.5,
            is_verified=True,
            uncertainty=0.15,
        ))

    crypto_dkim_status = (authentication.get("dkim") or {}).get("status")
    if crypto_dkim_status == "fail":
        ev_type = "auth.dkim.cryptographic_fail"
        obs = "Independent cryptographic DKIM verification failed against published DNS key."
        evidence.append(EvidenceObject(
            evidence_id=generate_evidence_id("authentication", ev_type, obs),
            investigation_id=investigation_id,
            type=ev_type,
            category="authentication",
            raw_observation=obs,
            interpretation="Direct cryptographic validation confirms header or body tampering.",
            conclusion="High probability of message modification or forgery.",
            source_component="authentication_verifier",
            source_reference="DKIM-Signature",
            detection_method="cryptographic",
            observed_at=now_iso,
            severity="high",
            direction="malicious",
            reliability=0.98,
            weight=3.5,
            is_verified=True,
            uncertainty=0.05,
        ))
    elif crypto_dkim_status == "pass":
        ev_type = "auth.dkim.cryptographic_pass"
        obs = "Direct cryptographic DKIM verification succeeded against published DNS key."
        evidence.append(EvidenceObject(
            evidence_id=generate_evidence_id("authentication", ev_type, obs),
            investigation_id=investigation_id,
            type=ev_type,
            category="authentication",
            raw_observation=obs,
            interpretation="Independent cryptographic verification guarantees message was not modified in transit.",
            conclusion="Confirmed cryptographic authenticity from signing domain.",
            source_component="authentication_verifier",
            source_reference="DKIM-Signature",
            detection_method="cryptographic",
            observed_at=now_iso,
            severity="informational",
            direction="legitimate",
            reliability=0.99,
            weight=2.0,
            is_verified=True,
            uncertainty=0.02,
        ))

    if spf_res in {"fail", "softfail", "permerror"}:
        ev_type = f"auth.spf.{spf_res}"
        obs = f"Receiving mail server reported SPF {spf_res}."
        evidence.append(EvidenceObject(
            evidence_id=generate_evidence_id("authentication", ev_type, obs),
            investigation_id=investigation_id,
            type=ev_type,
            category="authentication",
            raw_observation=obs,
            interpretation="Transmitting IP was not authorized by sender domain SPF policy.",
            conclusion="Unapproved relay transmission indicating potential spoofing.",
            source_component="authentication_verifier",
            source_reference="Received-SPF",
            detection_method="deterministic",
            observed_at=now_iso,
            severity="medium",
            direction="malicious",
            reliability=0.85,
            weight=2.0,
            is_verified=True,
            uncertainty=0.15,
        ))
    elif spf_res == "pass":
        ev_type = "auth.spf.pass"
        obs = "Receiving mail server reported SPF pass."
        evidence.append(EvidenceObject(
            evidence_id=generate_evidence_id("authentication", ev_type, obs),
            investigation_id=investigation_id,
            type=ev_type,
            category="authentication",
            raw_observation=obs,
            interpretation="Sending IP is explicitly designated as an authorized sender in domain SPF record.",
            conclusion="Sender host conforms to published sender policy.",
            source_component="authentication_verifier",
            source_reference="Received-SPF",
            detection_method="deterministic",
            observed_at=now_iso,
            severity="informational",
            direction="legitimate",
            reliability=0.85,
            weight=1.5,
            is_verified=True,
            uncertainty=0.10,
        ))

    if dmarc_res == "fail":
        ev_type = "auth.dmarc.fail"
        obs = "Receiving mail server reported DMARC policy evaluation failure."
        evidence.append(EvidenceObject(
            evidence_id=generate_evidence_id("authentication", ev_type, obs),
            investigation_id=investigation_id,
            type=ev_type,
            category="authentication",
            raw_observation=obs,
            interpretation="Sender failed DMARC alignment; neither aligned SPF nor aligned DKIM validated.",
            conclusion="Strong indicator of domain impersonation.",
            source_component="authentication_verifier",
            source_reference="Authentication-Results",
            detection_method="deterministic",
            observed_at=now_iso,
            severity="high",
            direction="malicious",
            reliability=0.90,
            weight=3.0,
            is_verified=True,
            uncertainty=0.10,
        ))
    elif dmarc_res == "pass":
        ev_type = "auth.dmarc.pass"
        obs = "Receiving mail server reported DMARC policy alignment pass."
        evidence.append(EvidenceObject(
            evidence_id=generate_evidence_id("authentication", ev_type, obs),
            investigation_id=investigation_id,
            type=ev_type,
            category="authentication",
            raw_observation=obs,
            interpretation="Sender passed DMARC with aligned domain credentials.",
            conclusion="Sender domain alignment verified.",
            source_component="authentication_verifier",
            source_reference="Authentication-Results",
            detection_method="deterministic",
            observed_at=now_iso,
            severity="informational",
            direction="legitimate",
            reliability=0.92,
            weight=2.0,
            is_verified=True,
            uncertainty=0.08,
        ))

    # 2. Header Inconsistencies
    for finding in header_analysis.get("findings") or []:
        htype = finding.get("type", "unknown_header_finding")
        explanation = finding.get("explanation") or finding.get("description") or "Header anomaly detected."

        if htype == "display_name_spoofing":
            evidence.append(EvidenceObject(
                evidence_id=generate_evidence_id("headers", htype, explanation),
                investigation_id=investigation_id,
                type=f"header.{htype}",
                category="headers",
                raw_observation=explanation,
                interpretation="Adversary disguised sender display name to resemble an authoritative email or organization.",
                conclusion="High-confidence deceptive impersonation.",
                source_component="header_analyzer",
                source_reference="From",
                detection_method="heuristic",
                observed_at=now_iso,
                severity="high",
                direction="malicious",
                reliability=0.88,
                weight=3.5,
                is_verified=False,
                uncertainty=0.12,
            ))
        elif htype == "from_reply_to_mismatch":
            evidence.append(EvidenceObject(
                evidence_id=generate_evidence_id("headers", htype, explanation),
                investigation_id=investigation_id,
                type=f"header.{htype}",
                category="headers",
                raw_observation=explanation,
                interpretation="Recipient replies are directed to an external mailbox different from the apparent sender.",
                conclusion="Potential reply-redirection attack.",
                source_component="header_analyzer",
                source_reference="Reply-To",
                detection_method="heuristic",
                observed_at=now_iso,
                severity="medium" if finding.get("severity") == "medium" else "low",
                direction="malicious",
                reliability=0.75,
                weight=2.0,
                is_verified=False,
                uncertainty=0.20,
            ))
        elif htype == "from_dkim_domain_mismatch":
            evidence.append(EvidenceObject(
                evidence_id=generate_evidence_id("headers", htype, explanation),
                investigation_id=investigation_id,
                type=f"header.{htype}",
                category="headers",
                raw_observation=explanation,
                interpretation="Message was cryptographically signed by a domain unrelated to the From address.",
                conclusion="DKIM domain divergence; sender domain is unauthenticated.",
                source_component="header_analyzer",
                source_reference="DKIM-Signature",
                detection_method="heuristic",
                observed_at=now_iso,
                severity="medium",
                direction="malicious",
                reliability=0.80,
                weight=1.8,
                is_verified=False,
                uncertainty=0.18,
            ))
        elif htype == "missing_received_headers":
            evidence.append(EvidenceObject(
                evidence_id=generate_evidence_id("headers", htype, explanation),
                investigation_id=investigation_id,
                type=f"header.{htype}",
                category="headers",
                raw_observation=explanation,
                interpretation="Email lacks standard transport Received headers, preventing relay traceability.",
                conclusion="Incomplete transport telemetry.",
                source_component="header_analyzer",
                source_reference="Received",
                detection_method="deterministic",
                observed_at=now_iso,
                severity="medium",
                direction="inconclusive",
                reliability=0.90,
                weight=1.5,
                is_verified=False,
                uncertainty=0.40,
            ))

    # 3. URL Analysis Evidence
    for url_res in url_analysis.get("results") or []:
        url_str = url_res.get("url", "")
        for ufind in url_res.get("findings") or []:
            utype = ufind.get("type", "unknown_url_finding")
            desc = ufind.get("description", "Suspicious URL characteristic.")

            weight_map = {
                "suspicious_scheme": (4.0, "critical", "malicious", 0.95),
                "embedded_credentials": (3.5, "high", "malicious", 0.90),
                "deceptive_brand_spoofing": (3.5, "high", "malicious", 0.85),
                "ip_address_host": (3.0, "high", "malicious", 0.90),
                "suspicious_encoding": (2.5, "high", "malicious", 0.80),
                "url_shortener": (2.0, "medium", "inconclusive", 0.70),
                "punycode_domain": (2.0, "medium", "malicious", 0.85),
                "backslash_character": (2.0, "medium", "malicious", 0.80),
                "excessive_subdomains": (1.5, "medium", "malicious", 0.75),
                "nonstandard_port": (1.5, "low", "inconclusive", 0.70),
                "unusual_tld": (1.0, "low", "inconclusive", 0.65),
            }

            weight, sev, direction, rel = weight_map.get(utype, (1.0, "low", "inconclusive", 0.60))

            evidence.append(EvidenceObject(
                evidence_id=generate_evidence_id("urls", utype, f"{url_str}:{desc}"),
                investigation_id=investigation_id,
                type=f"url.{utype}",
                category="urls",
                raw_observation=f"URL: {url_str} - {desc}",
                interpretation="Adversary utilizes deceptive or evasion-oriented URL architecture to mislead user.",
                conclusion=f"Hostile or deceptive hyperlink pattern: {utype}.",
                source_component="url_analyzer",
                source_reference=url_str,
                detection_method="heuristic",
                observed_at=now_iso,
                severity=sev,
                direction=direction,
                reliability=rel,
                weight=weight,
                is_verified=False,
                uncertainty=round(1.0 - rel, 2),
            ))

    # 4. Attachment Evidence
    attachments = parsed_email.get("attachments") or []
    for att in attachments:
        fn = att.get("filename") or "unknown_file"
        ext = Path(fn).suffix.lower()
        sha_val = att.get("sha256") or att.get("size")

        if ext in DANGEROUS_EXTENSIONS:
            evidence.append(EvidenceObject(
                evidence_id=generate_evidence_id("attachments", "dangerous_extension", f"{fn}:{sha_val}"),
                investigation_id=investigation_id,
                type="attachment.dangerous_executable",
                category="attachments",
                raw_observation=f"Attachment '{fn}' has dangerous executable extension '{ext}'.",
                interpretation="Email contains executable or script payload capable of arbitrary client-side code execution.",
                conclusion="Hostile payload delivery mechanism.",
                source_component="parser",
                source_reference=fn,
                detection_method="deterministic",
                observed_at=now_iso,
                severity="critical",
                direction="malicious",
                reliability=0.95,
                weight=4.5,
                is_verified=True,
                uncertainty=0.05,
            ))
        elif ext in ARCHIVE_EXTENSIONS:
            evidence.append(EvidenceObject(
                evidence_id=generate_evidence_id("attachments", "archive_file", f"{fn}:{sha_val}"),
                investigation_id=investigation_id,
                type="attachment.archive_container",
                category="attachments",
                raw_observation=f"Attachment '{fn}' is a compressed archive container ({ext}).",
                interpretation="Archives frequently obscure malware from perimeter content filters.",
                conclusion="Container file requiring deeper decompression inspection.",
                source_component="parser",
                source_reference=fn,
                detection_method="deterministic",
                observed_at=now_iso,
                severity="low",
                direction="inconclusive",
                reliability=0.85,
                weight=1.5,
                is_verified=True,
                uncertainty=0.25,
            ))

    # 5. Relay & Origin Evidence
    if relay_analysis.get("has_timing_anomalies"):
        evidence.append(EvidenceObject(
            evidence_id=generate_evidence_id("relay", "timing_anomaly", str(relay_analysis.get("anomalies"))),
            investigation_id=investigation_id,
            type="relay.timing_anomaly",
            category="relay",
            raw_observation="Negative hop transmission delay detected in Received headers.",
            interpretation="Hop timestamps go backwards in time, suggesting fabricated headers or misconfigured NTP.",
            conclusion="Transport header tampering or severe clock skew.",
            source_component="relay_analyzer",
            source_reference="Received",
            detection_method="deterministic",
            observed_at=now_iso,
            severity="medium",
            direction="malicious",
            reliability=0.75,
            weight=2.0,
            is_verified=False,
            uncertainty=0.25,
        ))

    return evidence
