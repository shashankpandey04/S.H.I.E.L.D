import re
from typing import Any

import dkim
import dns.exception
import dns.resolver


def parse_reported_authentication(headers: dict[str, Any]) -> dict[str, Any]:
    auth_headers = headers.get("authentication_headers") or {}
    auth_results_list = auth_headers.get("authentication_results") or []
    received_spf_list = auth_headers.get("received_spf") or []

    reported: dict[str, Any] = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
    }

    for header in auth_results_list:
        if not reported["spf"]:
            spf_match = re.search(r"\bspf=([a-zA-Z]+)", header, re.IGNORECASE)
            if spf_match:
                reported["spf"] = spf_match.group(1).lower()

        if not reported["dkim"]:
            dkim_match = re.search(r"\bdkim=([a-zA-Z]+)", header, re.IGNORECASE)
            if dkim_match:
                reported["dkim"] = dkim_match.group(1).lower()

        if not reported["dmarc"]:
            dmarc_match = re.search(r"\bdmarc=([a-zA-Z]+)", header, re.IGNORECASE)
            if dmarc_match:
                reported["dmarc"] = dmarc_match.group(1).lower()

    if not reported["spf"] and received_spf_list:
        for spf_header in received_spf_list:
            spf_match = re.search(r"^\s*([a-zA-Z]+)", spf_header)
            if spf_match:
                reported["spf"] = spf_match.group(1).lower()
                break

    return {
        "raw_headers": {
            "authentication_results": auth_results_list,
            "received_spf": received_spf_list,
            "dkim_signatures": auth_headers.get("dkim_signatures") or [],
            "arc_authentication_results": auth_headers.get("arc_authentication_results") or [],
        },
        "parsed": {
            "spf": {
                "result": reported["spf"],
                "note": "Reported by receiving mail server; unverified if headers were forged.",
            },
            "dkim": {
                "result": reported["dkim"],
                "note": "Reported by receiving mail server; unverified if headers were forged.",
            },
            "dmarc": {
                "result": reported["dmarc"],
                "note": "Reported by receiving mail server; unverified if headers were forged.",
            },
        },
    }


def parse_dkim_signatures(signatures: list[str]) -> list[dict[str, Any]]:
    parsed_sigs: list[dict[str, Any]] = []

    for sig in signatures:
        domain_match = re.search(r"(?:^|;)\s*d=([^;\s]+)", sig, re.IGNORECASE)
        selector_match = re.search(r"(?:^|;)\s*s=([^;\s]+)", sig, re.IGNORECASE)
        algo_match = re.search(r"(?:^|;)\s*a=([^;\s]+)", sig, re.IGNORECASE)
        identity_match = re.search(r"(?:^|;)\s*i=([^;\s]+)", sig, re.IGNORECASE)

        parsed_sigs.append({
            "domain": domain_match.group(1).lower().strip(".") if domain_match else None,
            "selector": selector_match.group(1) if selector_match else None,
            "algorithm": algo_match.group(1) if algo_match else None,
            "identity": identity_match.group(1) if identity_match else None,
            "raw": sig,
        })

    return parsed_sigs


def extract_domains(email_data: dict[str, Any]) -> dict[str, Any]:
    headers = email_data.get("headers") or {}
    sender_addresses = headers.get("sender") or []
    domains: dict[str, Any] = {
        "sender_domain": None,
        "return_path_domain": None,
        "dkim_domains": [],
    }

    if sender_addresses:
        sender = sender_addresses[0]
        if "@" in sender:
            domains["sender_domain"] = sender.rsplit("@", 1)[1].lower().strip(".")

    return_path = headers.get("return_path")
    if return_path:
        match = re.search(r"[\w.+%-]+@([\w.-]+)", return_path)
        if match:
            domains["return_path_domain"] = match.group(1).lower().strip(".")

    sig_headers = (email_data.get("authentication_headers") or {}).get("dkim_signatures") or []
    parsed_sigs = parse_dkim_signatures(sig_headers)
    dkim_domains = [s["domain"] for s in parsed_sigs if s.get("domain")]
    domains["dkim_domains"] = list(dict.fromkeys(dkim_domains))

    return domains


def lookup_txt_records(domain: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        answers = resolver.resolve(domain, "TXT")
        return [
            b"".join(record.strings).decode("utf-8", errors="replace")
            for record in answers
        ]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
        Exception,
    ):
        return []


def check_spf(domain: str | None) -> dict[str, Any]:
    if not domain:
        return {
            "status": "unknown",
            "records": [],
            "details": "Sender domain unavailable for SPF check.",
        }

    records = [
        record for record in lookup_txt_records(domain)
        if record.lower().startswith("v=spf1")
    ]

    if len(records) == 1:
        status = "configured"
        details = "An SPF record is published in DNS; the sending IP has not been evaluated."
    elif len(records) > 1:
        status = "invalid"
        details = "Multiple SPF records were found for domain (violates RFC 7208)."
    else:
        status = "missing"
        details = "No SPF record was found for sender domain."

    return {
        "status": status,
        "records": records,
        "details": details,
    }


def check_dmarc(domain: str | None) -> dict[str, Any]:
    if not domain:
        return {
            "status": "unknown",
            "records": [],
            "details": "Sender domain unavailable for DMARC check.",
        }

    records = [
        record for record in lookup_txt_records(f"_dmarc.{domain}")
        if record.lower().startswith("v=dmarc1")
    ]

    if not records and "." in domain:
        parts = domain.split(".")
        if len(parts) > 2:
            org_domain = ".".join(parts[-2:])
            records = [
                record for record in lookup_txt_records(f"_dmarc.{org_domain}")
                if record.lower().startswith("v=dmarc1")
            ]

    if len(records) == 1:
        status = "configured"
        details = "A DMARC policy record is published in DNS; policy enforcement has not been evaluated."
    elif len(records) > 1:
        status = "invalid"
        details = "Multiple DMARC records were found for domain."
    else:
        status = "missing"
        details = "No DMARC record was found for domain."

    return {
        "status": status,
        "records": records,
        "details": details,
    }


def check_dkim(
    signatures: list[dict[str, Any]],
    raw_eml_bytes: bytes | None = None,
) -> dict[str, Any]:
    if not signatures:
        return {
            "status": "missing",
            "signatures": [],
            "details": "No DKIM signature found in message.",
        }

    if raw_eml_bytes:
        try:
            verified = dkim.verify(raw_eml_bytes)
            if verified:
                return {
                    "status": "pass",
                    "signatures": signatures,
                    "details": "DKIM signature cryptographically verified against published public key.",
                }
            return {
                "status": "fail",
                "signatures": signatures,
                "details": "DKIM signature failed cryptographic verification.",
            }
        except (dkim.DKIMException, dns.exception.DNSException, Exception) as exc:
            return {
                "status": "unverified",
                "signatures": signatures,
                "details": f"DKIM signature detected, but cryptographic verification could not be completed ({type(exc).__name__}).",
            }

    return {
        "status": "unverified",
        "signatures": signatures,
        "details": "DKIM signature present, but cryptographic verification requires original raw message bytes and public key lookup.",
    }


def evaluate_dmarc(
    sender_domain: str | None,
    dmarc_record_check: dict[str, Any],
    dkim_check: dict[str, Any],
    reported_results: dict[str, Any],
) -> dict[str, Any]:
    if dmarc_record_check.get("status") == "missing":
        return {
            "status": "missing",
            "details": "DMARC cannot be evaluated because no DMARC record is published.",
        }

    if dmarc_record_check.get("status") == "invalid":
        return {
            "status": "invalid",
            "details": "DMARC record is invalid (e.g. multiple records).",
        }

    dkim_status = dkim_check.get("status")
    signatures = dkim_check.get("signatures", [])
    dkim_aligned = any(
        s.get("domain") and sender_domain and (
            s["domain"] == sender_domain or sender_domain.endswith(f".{s['domain']}")
        )
        for s in signatures
    )

    if dkim_status == "pass" and dkim_aligned:
        return {
            "status": "pass",
            "details": "DMARC passed based on cryptographically verified and aligned DKIM signature.",
        }

    if dkim_status == "fail":
        return {
            "status": "fail",
            "details": "DKIM signature failed cryptographic verification.",
        }

    reported_dmarc = reported_results.get("parsed", {}).get("dmarc", {}).get("result")
    if reported_dmarc in {"pass", "fail"}:
        return {
            "status": reported_dmarc,
            "details": f"DMARC was reported as '{reported_dmarc}' by receiving server headers; not independently verified.",
        }

    return {
        "status": "unverified",
        "details": "DMARC record is configured, but independent alignment verification cannot be completed without verified sending IP or verified DKIM.",
    }


def analyze_authentication(
    email_data: dict[str, Any],
    raw_eml_bytes: bytes | None = None,
) -> dict[str, Any]:
    domains = extract_domains(email_data)
    reported = parse_reported_authentication(email_data)
    sig_headers = (email_data.get("authentication_headers") or {}).get("dkim_signatures") or []
    parsed_sigs = parse_dkim_signatures(sig_headers)

    spf_check = check_spf(domains["sender_domain"])
    dmarc_check = check_dmarc(domains["sender_domain"])
    dkim_check = check_dkim(parsed_sigs, raw_eml_bytes)
    dmarc_evaluation = evaluate_dmarc(
        domains["sender_domain"],
        dmarc_check,
        dkim_check,
        reported,
    )

    return {
        "domains": domains,
        "reported_results": reported,
        "spf": spf_check,
        "dkim": dkim_check,
        "dmarc": dmarc_check,
        "dmarc_evaluation": dmarc_evaluation,
    }
