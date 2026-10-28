import re
from html import unescape
from html.parser import HTMLParser
from typing import Any

URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[^\s<>\"']+", re.IGNORECASE)
TRAILING_PUNCTUATION = ".,;:!?)]}>\`'\""


class EmailHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        for attribute, value in attrs:
            if attribute.lower() in {"href", "src"} and value:
                cleaned = unescape(value.strip())
                if cleaned and not cleaned.startswith(("#", "mailto:", "tel:")):
                    self.urls.append(cleaned)


def extract_text_urls(text: str | None) -> list[str]:
    if not text:
        return []

    decoded_text = unescape(text)

    return [
        match.group(0).rstrip(TRAILING_PUNCTUATION)
        for match in URL_PATTERN.finditer(decoded_text)
    ]


def extract_html_urls(html: str | None) -> list[str]:
    if not html:
        return []

    parser = EmailHTMLParser()

    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return []

    return parser.urls


def extract_email_urls(email_data: dict[str, Any]) -> dict[str, Any]:
    body = email_data.get("body") or {}

    text_urls = extract_text_urls(body.get("body_text"))
    html_urls = extract_html_urls(body.get("body_html"))

    dedup_text = list(dict.fromkeys(text_urls))
    dedup_html = list(dict.fromkeys(html_urls))
    all_urls = list(dict.fromkeys(dedup_text + dedup_html))

    return {
        "total": len(all_urls),
        "text_urls": dedup_text,
        "html_urls": dedup_html,
        "all_urls": all_urls,
    }
