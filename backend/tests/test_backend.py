import io
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import HTTPException, UploadFile
from pymongo.errors import PyMongoError
from starlette.datastructures import Headers

from api.v1.endpoints import emails, health
from services.authentication.verifier import (
    analyze_authentication,
    check_dkim,
    check_dmarc,
    check_spf,
    evaluate_dmarc,
    extract_domains,
    parse_reported_authentication,
)
from services.email.header_analyzer import analyze_header_consistency
from services.email.parser import extract_addresses, parse_eml
from services.email.risk_scorer import score_risk
from services.email.url_analyzer import analyze_email_urls, analyze_url
from services.email.url_extractor import (
    extract_email_urls,
    extract_html_urls,
    extract_text_urls,
)
from utils.hashing import calculate_sha256


def run_coro(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as exc:
        return exc.value


class EmailParserTests(unittest.TestCase):
    def test_extract_addresses(self):
        self.assertEqual(extract_addresses(""), [])
        self.assertEqual(
            extract_addresses("Alice <alice@example.com>, bob@example.com"),
            ["alice@example.com", "bob@example.com"],
        )

    def test_parse_valid_eml(self):
        raw = (
            b"From: Sender <sender@example.com>\r\n"
            b"To: Recipient <recipient@example.com>\r\n"
            b"Subject: Test Subject\r\n"
            b"Date: Wed, 28 Oct 2026 12:00:00 +0000\r\n"
            b"Message-ID: <12345@example.com>\r\n"
            b"Received: from mail.example.com by mx.example.com\r\n"
            b"Authentication-Results: mx.example.com; spf=pass; dkim=pass\r\n"
            b"\r\n"
            b"Plain body text."
        )
        parsed = parse_eml(raw, "message.eml")
        self.assertEqual(parsed["filename"], "message.eml")
        self.assertEqual(parsed["headers"]["subject"], "Test Subject")
        self.assertEqual(parsed["headers"]["sender"], ["sender@example.com"])
        self.assertEqual(parsed["headers"]["to"], ["recipient@example.com"])
        self.assertEqual(parsed["body"]["body_text"], "Plain body text.")
        self.assertEqual(len(parsed["headers"]["received"]), 1)
        self.assertEqual(len(parsed["authentication_headers"]["authentication_results"]), 1)

    def test_parse_multipart_message(self):
        boundary = b"boundary123"
        raw = (
            b"From: sender@example.com\r\n"
            b"To: rcpt@example.com\r\n"
            b"Subject: Multipart\r\n"
            b"Content-Type: multipart/mixed; boundary=\"boundary123\"\r\n"
            b"\r\n"
            b"--boundary123\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Text part\r\n"
            b"--boundary123\r\n"
            b"Content-Type: text/html\r\n"
            b"\r\n"
            b"<p>HTML part</p>\r\n"
            b"--boundary123\r\n"
            b"Content-Type: application/pdf\r\n"
            b"Content-Disposition: attachment; filename=\"document.pdf\"\r\n"
            b"\r\n"
            b"Dummy PDF binary\r\n"
            b"--boundary123--"
        )
        parsed = parse_eml(raw, "multi.eml")
        self.assertEqual(parsed["body"]["body_text"], "Text part")
        self.assertEqual(parsed["body"]["body_html"], "<p>HTML part</p>")
        self.assertEqual(len(parsed["attachments"]), 1)
        self.assertEqual(parsed["attachments"][0]["filename"], "document.pdf")
        self.assertEqual(parsed["attachments"][0]["content_type"], "application/pdf")
        self.assertEqual(parsed["attachments"][0]["size"], 16)

    def test_parse_malformed_email(self):
        raw = b"\xff\xfe\x00\x00Not a valid header block"
        parsed = parse_eml(raw, "malformed.eml")
        self.assertEqual(parsed["filename"], "malformed.eml")
        self.assertIsInstance(parsed["headers"], dict)


class URLExtractorTests(unittest.TestCase):
    def test_extract_text_urls(self):
        text = "Visit https://example.com/page. Also check http://test.org/path, and (https://sub.domain.co/)."
        urls = extract_text_urls(text)
        self.assertIn("https://example.com/page", urls)
        self.assertIn("http://test.org/path", urls)
        self.assertIn("https://sub.domain.co/", urls)

    def test_extract_html_urls(self):
        html = '<a href="https://example.com/link">Click</a><img src="https://example.com/img.png"><a href="#anchor">Ignored</a>'
        urls = extract_html_urls(html)
        self.assertIn("https://example.com/link", urls)
        self.assertIn("https://example.com/img.png", urls)
        self.assertNotIn("#anchor", urls)

    def test_duplicate_url_handling(self):
        email_data = {
            "body": {
                "body_text": "https://example.com https://example.com",
                "body_html": '<a href="https://example.com">link</a><a href="https://other.com">other</a>',
            }
        }
        res = extract_email_urls(email_data)
        self.assertEqual(res["total"], 2)
        self.assertEqual(res["text_urls"], ["https://example.com"])
        self.assertEqual(res["all_urls"], ["https://example.com", "https://other.com"])


class URLAnalyzerTests(unittest.TestCase):
    def test_ip_based_url(self):
        res = analyze_url("http://192.168.1.50/login")
        self.assertEqual(res["status"], "suspicious")
        self.assertEqual(res["host"], "192.168.1.50")
        finding_types = [f["type"] for f in res["findings"]]
        self.assertIn("ip_address_host", finding_types)

    def test_embedded_credentials(self):
        res = analyze_url("https://user:password@legit-looking.com/login")
        self.assertEqual(res["status"], "suspicious")
        finding_types = [f["type"] for f in res["findings"]]
        self.assertIn("embedded_credentials", finding_types)

    def test_punycode_domain(self):
        res = analyze_url("https://xn--e1afmkfd.xn--p1ai/path")
        self.assertEqual(res["status"], "suspicious")
        finding_types = [f["type"] for f in res["findings"]]
        self.assertIn("punycode_domain", finding_types)

    def test_url_shortener(self):
        res = analyze_url("https://bit.ly/3xyz")
        self.assertEqual(res["status"], "suspicious")
        finding_types = [f["type"] for f in res["findings"]]
        self.assertIn("url_shortener", finding_types)

    def test_suspicious_scheme(self):
        res = analyze_url("javascript:alert(document.cookie)")
        self.assertEqual(res["status"], "suspicious")
        finding_types = [f["type"] for f in res["findings"]]
        self.assertIn("suspicious_scheme", finding_types)

    def test_malformed_and_unsupported_urls(self):
        res = analyze_url("gopher://old-protocol.org")
        self.assertEqual(res["status"], "invalid")
        res2 = analyze_url("not a url at all")
        self.assertEqual(res2["status"], "invalid")

    def test_clean_url(self):
        res = analyze_url("https://www.google.com/search")
        self.assertEqual(res["status"], "no_obvious_indicators")
        self.assertEqual(res["findings"], [])


class AuthenticationVerifierTests(unittest.TestCase):
    def test_reported_authentication_parsing(self):
        email_data = {
            "authentication_headers": {
                "authentication_results": [
                    "mx.example.com; spf=pass (mail.example.com); dkim=pass header.d=example.com; dmarc=pass action=none"
                ],
                "received_spf": ["Pass (mx.example.com: domain of user@example.com designates 192.0.2.1 as permitted)"],
                "dkim_signatures": ["v=1; a=rsa-sha256; d=example.com; s=s2023; b=abc"],
                "arc_authentication_results": [],
            }
        }
        res = parse_reported_authentication(email_data)
        parsed = res["parsed"]
        self.assertEqual(parsed["spf"]["result"], "pass")
        self.assertEqual(parsed["dkim"]["result"], "pass")
        self.assertEqual(parsed["dmarc"]["result"], "pass")

    def test_missing_authentication_headers(self):
        email_data = {"authentication_headers": {}}
        res = parse_reported_authentication(email_data)
        parsed = res["parsed"]
        self.assertIsNone(parsed["spf"]["result"])
        self.assertIsNone(parsed["dkim"]["result"])
        self.assertIsNone(parsed["dmarc"]["result"])

    @patch("services.authentication.verifier.lookup_txt_records")
    def test_spf_dns_checks(self, mock_lookup):
        mock_lookup.return_value = ["v=spf1 include:_spf.example.com ~all"]
        configured = check_spf("example.com")
        self.assertEqual(configured["status"], "configured")

        mock_lookup.return_value = ["v=spf1 -all", "v=spf1 +all"]
        invalid = check_spf("example.com")
        self.assertEqual(invalid["status"], "invalid")

        mock_lookup.return_value = []
        missing = check_spf("example.com")
        self.assertEqual(missing["status"], "missing")

    def test_dkim_verification_states(self):
        missing = check_dkim([])
        self.assertEqual(missing["status"], "missing")

        sigs = [{"domain": "example.com", "selector": "s1"}]
        unverified = check_dkim(sigs, raw_eml_bytes=None)
        self.assertEqual(unverified["status"], "unverified")

        with patch("dkim.verify", return_value=True):
            verified = check_dkim(sigs, raw_eml_bytes=b"sample bytes")
            self.assertEqual(verified["status"], "pass")

        with patch("dkim.verify", return_value=False):
            failed = check_dkim(sigs, raw_eml_bytes=b"tampered bytes")
            self.assertEqual(failed["status"], "fail")


class HeaderAnalyzerTests(unittest.TestCase):
    def test_display_name_spoofing(self):
        email_data = {
            "headers": {
                "from": '"security@paypal.com" <scammer@evil.com>',
                "sender": ["scammer@evil.com"],
                "reply_to": [],
                "return_path": "<scammer@evil.com>",
                "received": ["hop1"],
            },
            "authentication_headers": {},
        }
        res = analyze_header_consistency(email_data)
        finding_types = [f["type"] for f in res["findings"]]
        self.assertIn("display_name_spoofing", finding_types)

    def test_reply_to_mismatch(self):
        email_data = {
            "headers": {
                "from": "CEO <ceo@corporate.com>",
                "sender": ["ceo@corporate.com"],
                "reply_to": ["ceo_private@gmail.com"],
                "return_path": "<ceo@corporate.com>",
                "received": ["hop1"],
            },
            "authentication_headers": {},
        }
        res = analyze_header_consistency(email_data)
        finding_types = [f["type"] for f in res["findings"]]
        self.assertIn("from_reply_to_mismatch", finding_types)
        mismatch_finding = [f for f in res["findings"] if f["type"] == "from_reply_to_mismatch"][0]
        self.assertEqual(mismatch_finding["severity"], "medium")

    def test_missing_received_headers(self):
        email_data = {
            "headers": {
                "from": "user@example.com",
                "sender": ["user@example.com"],
                "received": [],
            },
            "authentication_headers": {},
        }
        res = analyze_header_consistency(email_data)
        finding_types = [f["type"] for f in res["findings"]]
        self.assertIn("missing_received_headers", finding_types)


class RiskScorerTests(unittest.TestCase):
    def test_score_bounds_and_categories(self):
        clean_email = {"attachments": []}
        clean_auth = {}
        clean_urls = {"results": []}
        clean_headers = {"findings": []}
        low_res = score_risk(clean_email, clean_auth, clean_urls, clean_headers)
        self.assertGreaterEqual(low_res["score"], 0)
        self.assertLessEqual(low_res["score"], 24)
        self.assertEqual(low_res["category"], "low")

        high_risk_email = {"attachments": [{"filename": "invoice.exe"}]}
        high_risk_auth = {
            "reported_results": {"parsed": {"dmarc": {"result": "fail"}}},
            "dkim": {"status": "fail"},
        }
        high_risk_urls = {
            "results": [
                {
                    "findings": [
                        {"type": "suspicious_scheme"},
                        {"type": "embedded_credentials"},
                        {"type": "ip_address_host"},
                    ]
                }
            ]
        }
        high_risk_headers = {
            "findings": [{"type": "display_name_spoofing"}]
        }
        critical_res = score_risk(
            high_risk_email,
            high_risk_auth,
            high_risk_urls,
            high_risk_headers,
        )
        self.assertLessEqual(critical_res["score"], 100)
        self.assertGreaterEqual(critical_res["score"], 75)
        self.assertEqual(critical_res["category"], "critical")
        self.assertTrue(len(critical_res["limitations"]) > 0)


class EndpointTests(unittest.TestCase):
    def test_health_check(self):
        res = run_coro(health.health_check())
        self.assertEqual(res["status"], "healthy")
        self.assertEqual(res["service"], "S.H.I.E.L.D.")

    def test_upload_invalid_extension(self):
        file = UploadFile(
            filename="malicious.exe",
            file=io.BytesIO(b"binary"),
            headers=Headers({"content-disposition": "form-data; name=\"file\"; filename=\"malicious.exe\""}),
        )
        file.read = AsyncMock(return_value=b"binary")
        file.close = AsyncMock()

        with self.assertRaises(HTTPException) as ctx:
            run_coro(emails.upload_email(file))
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Only .eml files are supported", ctx.exception.detail)

    def test_upload_empty_file(self):
        file = UploadFile(
            filename="empty.eml",
            file=io.BytesIO(b""),
            headers=Headers({"content-disposition": "form-data; name=\"file\"; filename=\"empty.eml\""}),
        )
        file.read = AsyncMock(return_value=b"")
        file.close = AsyncMock()

        with self.assertRaises(HTTPException) as ctx:
            run_coro(emails.upload_email(file))
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("The uploaded file is empty", ctx.exception.detail)

    def test_upload_size_limit_exceeded(self):
        file = UploadFile(
            filename="huge.eml",
            file=io.BytesIO(b""),
            headers=Headers({"content-disposition": "form-data; name=\"file\"; filename=\"huge.eml\""}),
        )
        file.read = AsyncMock(return_value=b"X" * (emails.MAX_UPLOAD_SIZE + 10))
        file.close = AsyncMock()

        with self.assertRaises(HTTPException) as ctx:
            run_coro(emails.upload_email(file))
        self.assertEqual(ctx.exception.status_code, 413)

    @patch("api.v1.endpoints.emails.asyncio.to_thread")
    @patch("api.v1.endpoints.emails.emails_collection.insert_one", new_callable=AsyncMock)
    def test_upload_success_pipeline(self, mock_insert, mock_to_thread):
        async def dummy_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        mock_to_thread.side_effect = dummy_thread
        mock_insert.return_value = MagicMock(inserted_id="test-id")

        raw_eml = (
            b"From: Security <security@shield.local>\r\n"
            b"To: Analyst <analyst@shield.local>\r\n"
            b"Subject: Mission Brief\r\n"
            b"Received: from relay.local by mx.shield.local\r\n"
            b"\r\n"
            b"Check link: https://shield.local/briefing"
        )
        file = UploadFile(
            filename="briefing.eml",
            file=io.BytesIO(raw_eml),
            headers=Headers({"content-disposition": "form-data; name=\"file\"; filename=\"briefing.eml\""}),
        )
        file.read = AsyncMock(return_value=raw_eml)
        file.close = AsyncMock()

        with patch("api.v1.endpoints.emails.upload_email_file", return_value="2026/10/28/test.eml"):
            res = run_coro(emails.upload_email(file))
            self.assertEqual(res["filename"], "briefing.eml")
            self.assertIn("sha256", res)
            self.assertIn("risk_assessment", res)
            self.assertIn("header_analysis", res)
            self.assertIn("url_analysis", res)
            self.assertIn("authentication", res)
            self.assertEqual(mock_insert.call_count, 1)

    @patch("api.v1.endpoints.emails.asyncio.to_thread")
    @patch("api.v1.endpoints.emails.emails_collection.insert_one", new_callable=AsyncMock)
    def test_database_failure_cleanup(self, mock_insert, mock_to_thread):
        async def dummy_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        mock_to_thread.side_effect = dummy_thread
        mock_insert.side_effect = PyMongoError("Connection timeout")

        raw_eml = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Hi\r\n\r\nBody"
        file = UploadFile(
            filename="msg.eml",
            file=io.BytesIO(raw_eml),
            headers=Headers({"content-disposition": "form-data; name=\"file\"; filename=\"msg.eml\""}),
        )
        file.read = AsyncMock(return_value=raw_eml)
        file.close = AsyncMock()

        with patch("api.v1.endpoints.emails.upload_email_file", return_value="path.eml"), \
             patch("api.v1.endpoints.emails.delete_email_file") as mock_delete:
            with self.assertRaises(HTTPException) as ctx:
                run_coro(emails.upload_email(file))
            self.assertEqual(ctx.exception.status_code, 503)
            self.assertIn("Unable to save the email record", ctx.exception.detail)

    @patch("api.v1.endpoints.emails.asyncio.to_thread")
    def test_storage_failure(self, mock_to_thread):
        async def dummy_thread(func, *args, **kwargs):
            if func == emails.upload_email_file:
                raise Exception("Supabase S3 connection failed")
            return func(*args, **kwargs)

        mock_to_thread.side_effect = dummy_thread
        raw_eml = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Hi\r\n\r\nBody"
        file = UploadFile(
            filename="msg.eml",
            file=io.BytesIO(raw_eml),
            headers=Headers({"content-disposition": "form-data; name=\"file\"; filename=\"msg.eml\""}),
        )
        file.read = AsyncMock(return_value=raw_eml)
        file.close = AsyncMock()

        with self.assertRaises(HTTPException) as ctx:
            run_coro(emails.upload_email(file))
        self.assertEqual(ctx.exception.status_code, 503)

    @patch("api.v1.endpoints.emails.emails_collection.find")
    @patch("api.v1.endpoints.emails.emails_collection.count_documents", new_callable=AsyncMock)
    def test_list_emails_pagination(self, mock_count, mock_find):
        mock_count.return_value = 1
        fake_cursor = MagicMock()
        fake_cursor.sort.return_value = fake_cursor
        fake_cursor.skip.return_value = fake_cursor
        fake_cursor.limit.return_value = fake_cursor

        async def fake_iter():
            yield {"_id": "test-123", "filename": "sample.eml", "uploaded_at": datetime.now(timezone.utc)}

        fake_cursor.__aiter__ = lambda self: fake_iter()
        mock_find.return_value = fake_cursor

        res = run_coro(emails.list_emails(limit=10, skip=0))
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["limit"], 10)
        self.assertEqual(res["skip"], 0)
        self.assertEqual(len(res["emails"]), 1)
        self.assertEqual(res["emails"][0]["id"], "test-123")

    @patch("api.v1.endpoints.emails.emails_collection.find_one", new_callable=AsyncMock)
    def test_get_email_analysis_found_and_not_found(self, mock_find_one):
        mock_find_one.return_value = {
            "_id": "test-id",
            "filename": "email.eml",
            "status": "analyzed",
        }
        res = run_coro(emails.get_email_analysis("test-id"))
        self.assertEqual(res["id"], "test-id")

        mock_find_one.return_value = None
        with self.assertRaises(HTTPException) as ctx:
            run_coro(emails.get_email_analysis("nonexistent-id"))
        self.assertEqual(ctx.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
