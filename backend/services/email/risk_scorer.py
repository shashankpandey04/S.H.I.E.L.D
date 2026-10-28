from pathlib import Path
from typing import Any

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".vbs",
    ".js",
    ".bat",
    ".cmd",
    ".hta",
    ".iso",
    ".wsf",
    ".ps1",
    ".jar",
    ".com",
    ".pif",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
}

LIMITATIONS = [
    "Preliminary heuristic assessment; does not constitute a guarantee of safety or maliciousness.",
    "Attachments were inspected by file extension and MIME metadata only; dynamic sandbox execution was not performed.",
    "Extracted URLs were evaluated statically without active network requests or external threat reputation lookups.",
    "Authentication checks depend on available DNS records and provided headers; unauthenticated headers may be spoofed.",
]


def score_risk(
    parsed_email: dict[str, Any],
    authentication: dict[str, Any],
    url_analysis: dict[str, Any],
    header_analysis: dict[str, Any],
) -> dict[str, Any]:
    contributions: list[dict[str, Any]] = []

    url_findings = []
    seen_url_finding_types = set()
    for res in url_analysis.get("results") or []:
        for finding in res.get("findings") or []:
            ftype = finding.get("type")
            if ftype and ftype not in seen_url_finding_types:
                seen_url_finding_types.add(ftype)
                url_findings.append(finding)

    url_points = 0
    for finding in url_findings:
        ftype = finding.get("type")
        if ftype == "suspicious_scheme":
            pts = 30
            url_points += pts
            contributions.append({
                "source": "urls",
                "type": ftype,
                "severity": "critical",
                "points": pts,
                "description": finding.get("description", "Dangerous URL scheme detected."),
            })
        elif ftype == "embedded_credentials":
            pts = 25
            url_points += pts
            contributions.append({
                "source": "urls",
                "type": ftype,
                "severity": "high",
                "points": pts,
                "description": finding.get("description", "Embedded credentials in URL."),
            })
        elif ftype == "deceptive_brand_spoofing":
            pts = 25
            url_points += pts
            contributions.append({
                "source": "urls",
                "type": ftype,
                "severity": "high",
                "points": pts,
                "description": finding.get("description", "Brand spoofing indicator in URL hostname."),
            })
        elif ftype == "ip_address_host":
            pts = 20
            url_points += pts
            contributions.append({
                "source": "urls",
                "type": ftype,
                "severity": "high",
                "points": pts,
                "description": finding.get("description", "URL host is an IP address."),
            })
        elif ftype == "suspicious_encoding":
            pts = 15
            url_points += pts
            contributions.append({
                "source": "urls",
                "type": ftype,
                "severity": "high",
                "points": pts,
                "description": finding.get("description", "Deceptive percent-encoding in URL."),
            })
        elif ftype in {"url_shortener", "punycode_domain", "backslash_character", "excessive_subdomains"}:
            pts = 10
            url_points += pts
            contributions.append({
                "source": "urls",
                "type": ftype,
                "severity": "medium",
                "points": pts,
                "description": finding.get("description", "Suspicious URL structural indicator."),
            })
        elif ftype in {"unusual_tld", "nonstandard_port", "long_hostname", "hyphenated_hostname"}:
            pts = 5
            url_points += pts
            contributions.append({
                "source": "urls",
                "type": ftype,
                "severity": "low",
                "points": pts,
                "description": finding.get("description", "Minor anomalous URL pattern."),
            })

    reported_parsed = (authentication.get("reported_results") or {}).get("parsed") or {}
    reported_spf = (reported_parsed.get("spf") or {}).get("result")
    reported_dkim = (reported_parsed.get("dkim") or {}).get("result")
    reported_dmarc = (reported_parsed.get("dmarc") or {}).get("result")

    if reported_spf in {"fail", "softfail", "permerror"}:
        contributions.append({
            "source": "authentication",
            "type": "reported_spf_fail",
            "severity": "medium",
            "points": 15,
            "description": f"Receiving server reported SPF {reported_spf}.",
        })

    if reported_dkim == "fail":
        contributions.append({
            "source": "authentication",
            "type": "reported_dkim_fail",
            "severity": "medium",
            "points": 15,
            "description": "Receiving server reported DKIM signature verification failure.",
        })

    if reported_dmarc == "fail":
        contributions.append({
            "source": "authentication",
            "type": "reported_dmarc_fail",
            "severity": "high",
            "points": 20,
            "description": "Receiving server reported DMARC policy evaluation failure.",
        })

    dkim_status = (authentication.get("dkim") or {}).get("status")
    if dkim_status == "fail":
        contributions.append({
            "source": "authentication",
            "type": "independent_dkim_fail",
            "severity": "high",
            "points": 25,
            "description": "Cryptographic DKIM verification failed against the published DNS key.",
        })

    spf_status = (authentication.get("spf") or {}).get("status")
    dmarc_status = (authentication.get("dmarc") or {}).get("status")

    if spf_status == "invalid" or dmarc_status == "invalid":
        contributions.append({
            "source": "authentication",
            "type": "invalid_dns_policy_records",
            "severity": "medium",
            "points": 10,
            "description": "Conflicting or invalid SPF/DMARC records published in DNS.",
        })
    elif spf_status == "missing" and dmarc_status == "missing":
        contributions.append({
            "source": "authentication",
            "type": "missing_email_auth_records",
            "severity": "low",
            "points": 5,
            "description": "Domain lacks both SPF and DMARC policy records in DNS.",
        })

    for finding in header_analysis.get("findings") or []:
        htype = finding.get("type")
        if htype == "display_name_spoofing":
            contributions.append({
                "source": "headers",
                "type": htype,
                "severity": "high",
                "points": 30,
                "description": finding.get("description") or finding.get("explanation", "Display name spoofing detected."),
            })
        elif htype == "missing_from_header":
            contributions.append({
                "source": "headers",
                "type": htype,
                "severity": "high",
                "points": 20,
                "description": "From header is missing from message.",
            })
        elif htype == "from_reply_to_mismatch":
            pts = 15 if finding.get("severity") == "medium" else 5
            contributions.append({
                "source": "headers",
                "type": htype,
                "severity": finding.get("severity", "low"),
                "points": pts,
                "description": finding.get("explanation", "From and Reply-To domains mismatch."),
            })
        elif htype == "from_dkim_domain_mismatch":
            contributions.append({
                "source": "headers",
                "type": htype,
                "severity": "medium",
                "points": 10,
                "description": finding.get("explanation", "DKIM signing domain does not match sender domain."),
            })
        elif htype == "missing_received_headers":
            contributions.append({
                "source": "headers",
                "type": htype,
                "severity": "medium",
                "points": 10,
                "description": "Email lacks Received headers.",
            })
        elif htype == "from_return_path_mismatch":
            contributions.append({
                "source": "headers",
                "type": htype,
                "severity": "low",
                "points": 5,
                "description": finding.get("explanation", "From and Return-Path domains mismatch."),
            })

    attachments = parsed_email.get("attachments") or []
    has_dangerous_ext = False
    has_archive_ext = False
    for att in attachments:
        fn = att.get("filename") or ""
        ext = Path(fn).suffix.lower()
        if ext in DANGEROUS_EXTENSIONS:
            has_dangerous_ext = True
        elif ext in ARCHIVE_EXTENSIONS:
            has_archive_ext = True

    if has_dangerous_ext:
        contributions.append({
            "source": "attachments",
            "type": "dangerous_attachment_extension",
            "severity": "critical",
            "points": 30,
            "description": "Message includes an attachment with a dangerous executable file extension.",
        })
    elif has_archive_ext:
        contributions.append({
            "source": "attachments",
            "type": "archive_attachment",
            "severity": "low",
            "points": 10,
            "description": "Message includes an archive attachment (.zip, .rar, .7z) that requires inspection.",
        })

    raw_score = sum(c["points"] for c in contributions)
    score = max(0, min(100, raw_score))

    if score >= 75:
        category = "critical"
    elif score >= 50:
        category = "high"
    elif score >= 25:
        category = "moderate"
    else:
        category = "low"

    return {
        "score": score,
        "category": category,
        "findings": contributions,
        "limitations": LIMITATIONS,
    }
