import ipaddress
from typing import Any
from urllib.parse import unquote, urlsplit

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "ow.ly",
    "rebrand.ly",
    "bitly.com",
    "buff.ly",
    "goo.gl",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "work",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
    "top",
    "buzz",
}

SUSPICIOUS_SCHEMES = {
    "javascript",
    "data",
    "vbscript",
    "file",
}

KNOWN_BRANDS = {
    "paypal",
    "microsoft",
    "apple",
    "google",
    "netflix",
    "amazon",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "dhl",
    "fedex",
    "ups",
}


def analyze_url(url: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    normalized_url = url.strip()

    try:
        parsed = urlsplit(normalized_url)
        scheme = parsed.scheme.lower()

        if scheme in SUSPICIOUS_SCHEMES:
            findings.append({
                "type": "suspicious_scheme",
                "severity": "critical",
                "description": f"URL uses potentially dangerous '{scheme}:' scheme.",
            })
            return {
                "url": normalized_url,
                "status": "suspicious",
                "host": None,
                "findings": findings,
            }

        if scheme not in {"http", "https", "ftp"}:
            return {
                "url": normalized_url,
                "status": "invalid",
                "host": None,
                "findings": [
                    {
                        "type": "unsupported_scheme",
                        "severity": "medium",
                        "description": "URL does not use HTTP, HTTPS, or standard web schemes.",
                    }
                ],
            }

        hostname = parsed.hostname
        if not hostname:
            return {
                "url": normalized_url,
                "status": "invalid",
                "host": None,
                "findings": [
                    {
                        "type": "missing_hostname",
                        "severity": "medium",
                        "description": "URL is missing a valid hostname.",
                    }
                ],
            }

        hostname = hostname.rstrip(".").lower()

        is_ip_address = False
        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            if hostname.isdigit():
                try:
                    ipaddress.ip_address(int(hostname))
                    is_ip_address = True
                except ValueError:
                    is_ip_address = False

        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            findings.append({
                "type": "embedded_credentials",
                "severity": "high",
                "description": (
                    "URL contains credentials or deceptive '@' in authority, "
                    "which can disguise the actual destination."
                ),
            })

        if is_ip_address:
            findings.append({
                "type": "ip_address_host",
                "severity": "high",
                "description": "URL uses an IP address instead of a registered domain name.",
            })

        if hostname in SHORTENER_DOMAINS:
            findings.append({
                "type": "url_shortener",
                "severity": "medium",
                "description": (
                    "URL uses a known link-shortening service, "
                    "which can conceal the final destination."
                ),
            })

        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append({
                "type": "punycode_domain",
                "severity": "medium",
                "description": (
                    "Hostname contains a punycode label, indicating "
                    "possible internationalized-domain spoofing."
                ),
            })

        decoded_url = unquote(normalized_url)
        lower_raw = normalized_url.lower()
        if "%25" in lower_raw or "%00" in lower_raw or "%2e%2e" in lower_raw:
            findings.append({
                "type": "suspicious_encoding",
                "severity": "high",
                "description": "URL contains deceptive or obfuscated percent-encoding.",
            })

        if "\\" in normalized_url or "\\" in decoded_url:
            findings.append({
                "type": "backslash_character",
                "severity": "medium",
                "description": (
                    "URL contains a backslash, which may cause ambiguous "
                    "path and authority interpretation."
                ),
            })

        labels = hostname.split(".")
        if len(labels) >= 2 and labels[-1] in SUSPICIOUS_TLDS:
            findings.append({
                "type": "unusual_tld",
                "severity": "low",
                "description": (
                    f"Hostname uses the .{labels[-1]} top-level domain. "
                    "This alone does not indicate malicious activity."
                ),
            })

        if len(labels) > 4 and not is_ip_address:
            findings.append({
                "type": "excessive_subdomains",
                "severity": "medium",
                "description": f"Hostname contains {len(labels)} subdomain levels.",
            })

        if hostname.count("-") >= 3:
            findings.append({
                "type": "hyphenated_hostname",
                "severity": "low",
                "description": "Hostname contains multiple hyphens.",
            })

        if len(hostname) > 60:
            findings.append({
                "type": "long_hostname",
                "severity": "low",
                "description": "Hostname is unusually long.",
            })

        if parsed.port is not None and parsed.port not in {80, 443, 8080, 8443}:
            findings.append({
                "type": "nonstandard_port",
                "severity": "low",
                "description": f"URL specifies nonstandard port {parsed.port}.",
            })

        if len(labels) >= 2 and not is_ip_address:
            registered_domain = f"{labels[-2]}.{labels[-1]}"
            for brand in KNOWN_BRANDS:
                if brand in hostname:
                    if brand not in registered_domain:
                        findings.append({
                            "type": "deceptive_brand_spoofing",
                            "severity": "high",
                            "description": (
                                f"Hostname contains trusted brand keyword '{brand}' "
                                f"on an unrelated domain ({hostname})."
                            ),
                        })
                        break

        status = "suspicious" if findings else "no_obvious_indicators"

        return {
            "url": normalized_url,
            "status": status,
            "host": hostname,
            "findings": findings,
        }

    except Exception:
        return {
            "url": normalized_url,
            "status": "invalid",
            "host": None,
            "findings": [
                {
                    "type": "malformed_url",
                    "severity": "medium",
                    "description": "URL could not be parsed safely.",
                }
            ],
        }


def analyze_email_urls(url_data: dict[str, Any]) -> dict[str, Any]:
    urls = url_data.get("all_urls", [])
    results = [analyze_url(url) for url in urls]

    suspicious_count = sum(result["status"] == "suspicious" for result in results)
    invalid_count = sum(result["status"] == "invalid" for result in results)

    return {
        "total": len(results),
        "suspicious_count": suspicious_count,
        "invalid_count": invalid_count,
        "results": results,
    }
