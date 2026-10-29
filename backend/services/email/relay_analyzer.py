import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?\b"
)

INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def is_ip_private_or_internal(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


def extract_ip_from_clause(clause: str) -> str | None:
    match_v4 = IPV4_PATTERN.search(clause)
    if match_v4:
        return match_v4.group(0)
    match_v6 = IPV6_PATTERN.search(clause)
    if match_v6 and ":" in match_v6.group(0) and len(match_v6.group(0)) > 3:
        try:
            ipaddress.ip_address(match_v6.group(0))
            return match_v6.group(0)
        except ValueError:
            pass
    return None


def parse_received_hop(raw_header: str, hop_index: int) -> dict[str, Any]:
    cleaned = re.sub(r"\s+", " ", raw_header).strip()

    date_str = None
    header_body = cleaned
    if ";" in cleaned:
        parts = cleaned.rsplit(";", 1)
        header_body = parts[0].strip()
        date_str = parts[1].strip()

    timestamp_dt = None
    if date_str:
        try:
            timestamp_dt = parsedate_to_datetime(date_str)
            if timestamp_dt.tzinfo is None:
                timestamp_dt = timestamp_dt.replace(tzinfo=timezone.utc)
        except Exception:
            timestamp_dt = None

    from_match = re.search(r"\bfrom\s+([^\s;()]+)(?:\s+\(([^()]+)\))?", header_body, re.IGNORECASE)
    by_match = re.search(r"\bby\s+([^\s;()]+)", header_body, re.IGNORECASE)
    with_match = re.search(r"\bwith\s+([^\s;()]+)", header_body, re.IGNORECASE)
    tls_match = re.search(r"\b(?:tls|cipher|version)=([^\s;()]+)", header_body, re.IGNORECASE)

    from_host = from_match.group(1) if from_match else None
    from_details = from_match.group(2) if from_match and from_match.group(2) else ""
    by_host = by_match.group(1) if by_match else None
    protocol = with_match.group(1) if with_match else None
    tls = tls_match.group(0) if tls_match else None

    from_ip = extract_ip_from_clause(from_details) if from_details else None
    if not from_ip and from_host:
        from_ip = extract_ip_from_clause(from_host)

    is_internal = is_ip_private_or_internal(from_ip) if from_ip else None

    return {
        "hop_index": hop_index,
        "from_host": from_host,
        "from_ip": from_ip,
        "is_private_ip": is_internal,
        "by_host": by_host,
        "protocol": protocol,
        "tls": tls,
        "raw_date": date_str,
        "timestamp": timestamp_dt.isoformat() if timestamp_dt else None,
        "_dt": timestamp_dt,
        "raw": cleaned,
    }


def analyze_relays(received_headers: list[str]) -> dict[str, Any]:
    if not received_headers:
        return {
            "total_hops": 0,
            "hops": [],
            "origin_candidates": [],
            "anomalies": ["no_received_headers"],
            "has_timing_anomalies": False,
        }

    parsed_hops = []
    # Reverse so hop 0 is origin and hop N is destination
    chronological_headers = list(reversed(received_headers))
    for idx, hdr in enumerate(chronological_headers):
        parsed_hops.append(parse_received_hop(hdr, idx))

    anomalies: list[str] = []
    timing_anomalies = False

    for i in range(len(parsed_hops) - 1):
        curr_hop = parsed_hops[i]
        next_hop = parsed_hops[i + 1]
        dt_curr = curr_hop.get("_dt")
        dt_next = next_hop.get("_dt")

        if dt_curr and dt_next:
            diff_seconds = (dt_next - dt_curr).total_seconds()
            curr_hop["delay_to_next_hop_seconds"] = diff_seconds
            if diff_seconds < -180:
                timing_anomalies = True
                anomalies.append(f"negative_delay_hop_{i}_to_{i+1}")

    candidates: list[dict[str, Any]] = []
    for hop in parsed_hops:
        ip = hop.get("from_ip")
        if ip and not hop.get("is_private_ip"):
            confidence = 0.95 if hop["hop_index"] == 0 else max(0.4, 0.9 - (hop["hop_index"] * 0.15))
            candidates.append({
                "ip": ip,
                "host": hop.get("from_host"),
                "hop_index": hop["hop_index"],
                "confidence": round(confidence, 2),
                "is_first_public_relay": len(candidates) == 0,
            })

    # Clean internal dt reference before returning
    for hop in parsed_hops:
        hop.pop("_dt", None)

    return {
        "total_hops": len(parsed_hops),
        "hops": parsed_hops,
        "origin_candidates": candidates,
        "primary_origin": candidates[0] if candidates else None,
        "anomalies": anomalies,
        "has_timing_anomalies": timing_anomalies,
    }
