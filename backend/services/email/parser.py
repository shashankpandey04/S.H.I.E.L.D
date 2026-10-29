from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
import hashlib
from typing import Any


def extract_addresses(value: str | None) -> list[str]:
    if not value:
        return []

    return [
        address
        for _, address in getaddresses([str(value)])
        if address
    ]


def extract_body(message: Any) -> dict[str, str | None]:
    body_text_parts: list[str] = []
    body_html_parts: list[str] = []

    parts = message.walk() if message.is_multipart() else [message]

    for part in parts:
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue

        content_str = None
        try:
            content = part.get_content()
            if isinstance(content, str):
                content_str = content
        except Exception:
            try:
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes):
                    charset = part.get_content_charset() or "utf-8"
                    content_str = payload.decode(charset, errors="replace")
            except Exception:
                content_str = None

        if content_str is not None:
            if content_type == "text/plain":
                body_text_parts.append(content_str)
            elif content_type == "text/html":
                body_html_parts.append(content_str)

    return {
        "body_text": "\n".join(body_text_parts) if body_text_parts else None,
        "body_html": "\n".join(body_html_parts) if body_html_parts else None,
    }


def extract_attachments(message: Any) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = part.get_content_disposition()

        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            if isinstance(payload, str):
                payload_bytes = payload.encode("utf-8", errors="replace")
            else:
                payload_bytes = payload

            attachments.append({
                "filename": filename or "unnamed_attachment",
                "content_type": part.get_content_type(),
                "size": len(payload_bytes),
                "sha256": hashlib.sha256(payload_bytes).hexdigest(),
                "md5": hashlib.md5(payload_bytes).hexdigest(),
            })

    return attachments


def parse_eml(file_data: bytes, filename: str) -> dict[str, Any]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(file_data)
    except Exception:
        message = BytesParser(policy=policy.compat32).parsebytes(file_data)

    raw_date = message.get("Date")
    parsed_date = None

    if raw_date:
        try:
            parsed_date = parsedate_to_datetime(str(raw_date)).isoformat()
        except (TypeError, ValueError, OverflowError):
            parsed_date = str(raw_date)

    body = extract_body(message)

    from_header = str(message.get("From")) if message.get("From") is not None else None
    sender_addresses = extract_addresses(from_header)
    to_header = str(message.get("To")) if message.get("To") is not None else None
    recipient_addresses = extract_addresses(to_header)
    cc_header = str(message.get("Cc")) if message.get("Cc") is not None else None
    bcc_header = str(message.get("Bcc")) if message.get("Bcc") is not None else None
    reply_to_header = str(message.get("Reply-To")) if message.get("Reply-To") is not None else None

    return {
        "filename": filename,
        "headers": {
            "subject": str(message.get("Subject")) if message.get("Subject") is not None else None,
            "from": from_header,
            "sender": sender_addresses,
            "to": recipient_addresses,
            "recipient": recipient_addresses,
            "cc": extract_addresses(cc_header),
            "bcc": extract_addresses(bcc_header),
            "reply_to": extract_addresses(reply_to_header),
            "return_path": str(message.get("Return-Path")) if message.get("Return-Path") is not None else None,
            "date": parsed_date,
            "message_id": str(message.get("Message-ID")) if message.get("Message-ID") is not None else None,
            "received": [str(value) for value in (message.get_all("Received") or [])],
        },
        "authentication_headers": {
            "authentication_results": [
                str(value)
                for value in (message.get_all("Authentication-Results") or [])
            ],
            "received_spf": [
                str(value)
                for value in (message.get_all("Received-SPF") or [])
            ],
            "dkim_signatures": [
                str(value)
                for value in (message.get_all("DKIM-Signature") or [])
            ],
            "arc_authentication_results": [
                str(value)
                for value in (message.get_all("ARC-Authentication-Results") or [])
            ],
        },
        "body": body,
        "attachments": extract_attachments(message),
    }
