import re
from email.utils import parseaddr
from typing import Any

FREE_WEBMAILS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "icloud.com",
    "mail.com",
    "zoho.com",
    "protonmail.com",
    "proton.me",
}


def extract_domain(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower().strip(".>")


def analyze_header_consistency(email_data: dict[str, Any]) -> dict[str, Any]:
    headers = email_data.get("headers") or {}
    auth_headers = email_data.get("authentication_headers") or {}

    from_header = headers.get("from")
    sender_addresses = headers.get("sender") or []
    reply_to_addresses = headers.get("reply_to") or []
    return_path = headers.get("return_path")
    received_headers = headers.get("received") or []
    dkim_signatures = auth_headers.get("dkim_signatures") or []

    findings: list[dict[str, str]] = []

    from_domain = None
    if sender_addresses:
        from_domain = extract_domain(sender_addresses[0])

    reply_to_domains = [
        d for d in (extract_domain(addr) for addr in reply_to_addresses) if d
    ]
    reply_to_domains = list(dict.fromkeys(reply_to_domains))

    return_path_domain = None
    if return_path:
        match = re.search(r"[\w.+%-]+@([\w.-]+)", return_path)
        if match:
            return_path_domain = match.group(1).lower().strip(".")

    dkim_domains = []
    for sig in dkim_signatures:
        match = re.search(r"(?:^|;)\s*d=([^;\s]+)", sig, re.IGNORECASE)
        if match:
            dkim_domains.append(match.group(1).lower().strip("."))
    dkim_domains = list(dict.fromkeys(dkim_domains))

    if not from_header and not sender_addresses:
        findings.append({
            "type": "missing_from_header",
            "severity": "high",
            "evidence": "No From header or sender address present.",
            "explanation": "RFC 5322 requires a valid From header specifying the author mailbox.",
        })
    elif len(sender_addresses) > 1:
        findings.append({
            "type": "multiple_from_addresses",
            "severity": "medium",
            "evidence": f"Multiple sender addresses found in From: {sender_addresses}.",
            "explanation": "Multiple mailboxes in From without a distinguishing Sender header violates standard conventions.",
        })

    if from_header:
        realname, email_addr = parseaddr(from_header)
        if realname and ("@" in realname or ".com" in realname.lower() or ".org" in realname.lower()):
            realname_domain = extract_domain(realname)
            actual_domain = extract_domain(email_addr)
            if realname_domain and actual_domain and realname_domain != actual_domain:
                findings.append({
                    "type": "display_name_spoofing",
                    "severity": "high",
                    "evidence": f"Display name '{realname}' mimics a different domain than actual address '{email_addr}'.",
                    "explanation": "Deceptive display names are commonly used in social engineering to disguise untrusted addresses.",
                })

    if from_domain and reply_to_domains:
        mismatched_replies = [d for d in reply_to_domains if d != from_domain]
        if mismatched_replies:
            is_freemail_redirect = any(d in FREE_WEBMAILS for d in mismatched_replies) and from_domain not in FREE_WEBMAILS
            severity = "medium" if is_freemail_redirect else "low"
            findings.append({
                "type": "from_reply_to_mismatch",
                "severity": severity,
                "evidence": f"From domain '{from_domain}' differs from Reply-To domain(s): {', '.join(mismatched_replies)}.",
                "explanation": "Replies are routed to a different domain. Common for legitimate marketing or ticketing, but also used in phishing to harvest responses.",
            })

    if from_domain and return_path_domain and return_path_domain != from_domain:
        findings.append({
            "type": "from_return_path_mismatch",
            "severity": "low",
            "evidence": f"From domain '{from_domain}' differs from Return-Path domain '{return_path_domain}'.",
            "explanation": "Envelope bounce address belongs to a different domain than author address. Typical for third-party email service providers.",
        })

    if from_domain and dkim_domains:
        aligned = any(
            d == from_domain or from_domain.endswith(f".{d}") or d.endswith(f".{from_domain}")
            for d in dkim_domains
        )
        if not aligned:
            findings.append({
                "type": "from_dkim_domain_mismatch",
                "severity": "medium",
                "evidence": f"DKIM signing domain(s) ({', '.join(dkim_domains)}) do not align with From domain '{from_domain}'.",
                "explanation": "The email was signed by a third-party domain rather than the author domain.",
            })

    hops_count = len(received_headers)
    if hops_count == 0:
        findings.append({
            "type": "missing_received_headers",
            "severity": "medium",
            "evidence": "No Received headers present in email.",
            "explanation": "Legitimate SMTP delivery records intermediate hops in Received headers.",
        })
    elif hops_count > 12:
        findings.append({
            "type": "excessive_received_hops",
            "severity": "low",
            "evidence": f"Email traversed {hops_count} intermediate relay hops.",
            "explanation": "An unusually high hop count may indicate routing loops or multiple relay intermediaries.",
        })

    return {
        "total_findings": len(findings),
        "inconsistencies_detected": bool(findings),
        "domains": {
            "from_domain": from_domain,
            "reply_to_domains": reply_to_domains,
            "return_path_domain": return_path_domain,
            "dkim_domains": dkim_domains,
        },
        "received_hops_count": hops_count,
        "findings": findings,
    }
