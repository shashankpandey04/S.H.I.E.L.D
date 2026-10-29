import asyncio
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import HTTPException
from core.security import (
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from schemas.auth import UserLoginRequest, UserRegisterRequest
from schemas.evidence import EvidenceObject
from schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationNoteRequest,
    InvestigationUpdateRequest,
)
from services.auth import auth_service
from services.email.relay_analyzer import (
    analyze_relays,
    extract_ip_from_clause,
    is_ip_private_or_internal,
    parse_received_hop,
)
from services.evidence.normalizer import normalize_forensic_evidence
from services.investigation.graph_service import (
    correlate_email_campaigns,
    index_email_graph_entities,
)
from services.investigation.report_service import generate_forensic_report
from services.scoring.formula_scorer import calculate_formula_score
from services.scoring.subjective_logic import (
    Opinion,
    evaluate_subjective_logic,
    evidence_to_opinion,
    fuse_averaging,
    fuse_consensus,
)
from api.v1.endpoints import auth as auth_endpoint
from api.v1.endpoints import investigations as inv_endpoint


def run_coro(coro):
    try:
        while True:
            coro.send(None)
    except StopIteration as exc:
        return exc.value


class SecurityCoreTests(unittest.TestCase):
    def test_password_hashing_and_verification(self):
        plain = "TopSecretPassword123!"
        hashed = hash_password(plain)
        self.assertNotEqual(plain, hashed)
        self.assertTrue(hashed.startswith("pbkdf2_sha256$600000$"))
        self.assertTrue(verify_password(plain, hashed))
        self.assertFalse(verify_password("WrongPassword!", hashed))
        self.assertFalse(verify_password(plain, "corrupted$hash"))

    def test_jwt_access_token_creation_and_decoding(self):
        token, expires = create_access_token("user-uuid-1", "agent@shield.local", "analyst")
        self.assertIsInstance(token, str)
        self.assertIsInstance(expires, datetime)

        payload = decode_access_token(token)
        self.assertEqual(payload["sub"], "user-uuid-1")
        self.assertEqual(payload["email"], "agent@shield.local")
        self.assertEqual(payload["role"], "analyst")
        self.assertEqual(payload["type"], "access")

    def test_jwt_invalid_and_expired(self):
        with self.assertRaises(HTTPException) as ctx:
            decode_access_token("not-a-valid-token")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_refresh_token_hashing(self):
        raw = generate_refresh_token()
        hashed = hash_refresh_token(raw)
        self.assertEqual(len(hashed), 64)
        self.assertEqual(hash_refresh_token(raw), hashed)


class AuthServiceTests(unittest.TestCase):
    @patch("services.auth.auth_service.users_collection.find_one", new_callable=AsyncMock)
    @patch("services.auth.auth_service.users_collection.insert_one", new_callable=AsyncMock)
    def test_register_user_success(self, mock_insert, mock_find):
        mock_find.return_value = None
        req = UserRegisterRequest(email="coulson@shield.local", password="Level7Password!")
        res = run_coro(auth_service.register_user(req))
        self.assertEqual(res["email"], "coulson@shield.local")
        self.assertEqual(res["role"], "user")
        self.assertIn("id", res)
        self.assertEqual(mock_insert.call_count, 1)

    @patch("services.auth.auth_service.users_collection.find_one", new_callable=AsyncMock)
    def test_register_duplicate_conflict(self, mock_find):
        mock_find.return_value = {"_id": "existing-id", "email": "coulson@shield.local"}
        req = UserRegisterRequest(email="coulson@shield.local", password="Level7Password!")
        with self.assertRaises(HTTPException) as ctx:
            run_coro(auth_service.register_user(req))
        self.assertEqual(ctx.exception.status_code, 409)

    @patch("services.auth.auth_service.users_collection.find_one", new_callable=AsyncMock)
    @patch("services.auth.auth_service.users_collection.update_one", new_callable=AsyncMock)
    @patch("services.auth.auth_service.refresh_tokens_collection.insert_one", new_callable=AsyncMock)
    def test_authenticate_user_success(self, mock_rt_insert, mock_update, mock_find):
        pwd_hash = hash_password("ValidPassword123")
        mock_find.return_value = {
            "_id": "user-123",
            "email": "fury@shield.local",
            "password_hash": pwd_hash,
            "role": "director",
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        }
        req = UserLoginRequest(email="fury@shield.local", password="ValidPassword123")
        res = run_coro(auth_service.authenticate_user(req))
        self.assertIn("access_token", res)
        self.assertIn("refresh_token", res)
        self.assertEqual(res["user"]["email"], "fury@shield.local")

    @patch("services.auth.auth_service.refresh_tokens_collection.find_one", new_callable=AsyncMock)
    @patch("services.auth.auth_service.refresh_tokens_collection.update_many", new_callable=AsyncMock)
    def test_refresh_token_replay_attack_revokes_family(self, mock_update_many, mock_find):
        mock_find.return_value = {
            "_id": "token-old",
            "family_id": "family-xyz",
            "revoked_at": datetime.now(timezone.utc) - timedelta(minutes=5),
            "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        }
        with self.assertRaises(HTTPException) as ctx:
            run_coro(auth_service.refresh_tokens("replayed-token"))
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("Token reuse detected", ctx.exception.detail)
        self.assertEqual(mock_update_many.call_count, 1)


class RelayAnalyzerTests(unittest.TestCase):
    def test_is_ip_private(self):
        self.assertTrue(is_ip_private_or_internal("10.0.0.1"))
        self.assertTrue(is_ip_private_or_internal("192.168.1.1"))
        self.assertTrue(is_ip_private_or_internal("172.16.0.5"))
        self.assertTrue(is_ip_private_or_internal("127.0.0.1"))
        self.assertFalse(is_ip_private_or_internal("8.8.8.8"))
        self.assertFalse(is_ip_private_or_internal("198.51.100.24"))

    def test_extract_ip_from_clause(self):
        self.assertEqual(extract_ip_from_clause("mail.example.com [198.51.100.2]"), "198.51.100.2")
        self.assertEqual(extract_ip_from_clause("(no-ip-here)"), None)

    def test_parse_received_hops_and_anomalies(self):
        headers = [
            "from mx.perimeter.local by internal.local; Wed, 28 Oct 2026 12:02:00 +0000",
            "from mail.external.com ([198.51.100.15]) by mx.perimeter.local with ESMTPS; Wed, 28 Oct 2026 12:01:00 +0000",
            "from client.sender.net ([10.0.0.50]) by mail.external.com; Wed, 28 Oct 2026 12:00:00 +0000",
        ]
        res = analyze_relays(headers)
        self.assertEqual(res["total_hops"], 3)
        self.assertFalse(res["has_timing_anomalies"])
        self.assertIsNotNone(res["primary_origin"])
        self.assertEqual(res["primary_origin"]["ip"], "198.51.100.15")


class EvidenceAndScoringTests(unittest.TestCase):
    def test_normalize_forensic_evidence(self):
        parsed = {
            "headers": {"received": ["from a by b; Wed, 28 Oct 2026 12:00:00 +0000"]},
            "attachments": [{"filename": "trojan.exe", "sha256": "abcdef123456"}],
        }
        auth = {
            "reported_results": {"parsed": {"spf": {"result": "fail"}, "dkim": {"result": "pass"}}},
            "dkim": {"status": "fail"},
        }
        urls = {
            "results": [
                {
                    "url": "http://192.168.1.1/login",
                    "findings": [{"type": "ip_address_host", "description": "IP host"}],
                }
            ]
        }
        headers = {
            "findings": [{"type": "display_name_spoofing", "explanation": "Spoofed display name"}]
        }
        relays = {"has_timing_anomalies": False}

        ev_list = normalize_forensic_evidence(parsed, auth, urls, headers, relays, investigation_id="inv-1")
        self.assertTrue(len(ev_list) >= 4)
        types = [e.type for e in ev_list]
        self.assertIn("attachment.dangerous_executable", types)
        self.assertIn("auth.dkim.cryptographic_fail", types)
        self.assertIn("header.display_name_spoofing", types)
        self.assertIn("url.ip_address_host", types)

    def test_formula_scoring_bounds_and_bands(self):
        ev1 = EvidenceObject(
            evidence_id="ev1",
            type="attachment.dangerous_executable",
            category="attachments",
            raw_observation="exe attached",
            interpretation="executable",
            conclusion="danger",
            source_component="parser",
            detection_method="deterministic",
            observed_at=datetime.now(timezone.utc).isoformat(),
            severity="critical",
            direction="malicious",
            reliability=0.95,
            weight=4.5,
        )
        ev2 = EvidenceObject(
            evidence_id="ev2",
            type="auth.dkim.cryptographic_fail",
            category="authentication",
            raw_observation="dkim failed",
            interpretation="signature mismatch",
            conclusion="tampered",
            source_component="verifier",
            detection_method="cryptographic",
            observed_at=datetime.now(timezone.utc).isoformat(),
            severity="high",
            direction="malicious",
            reliability=0.98,
            weight=3.5,
        )

        res = calculate_formula_score([ev1, ev2])
        self.assertGreaterEqual(res.final_score, 80)
        self.assertEqual(res.band, "Critical")
        self.assertIn("clamp", res.formula)
        self.assertEqual(len(res.contributions), 2)

    def test_subjective_logic_opinion_properties(self):
        op = Opinion(belief=0.6, disbelief=0.2, uncertainty=0.2, base_rate=0.5)
        self.assertAlmostEqual(op.belief + op.disbelief + op.uncertainty, 1.0)
        self.assertAlmostEqual(op.projected_probability, 0.7)

    def test_subjective_logic_consensus_fusion(self):
        op_a = Opinion(belief=0.5, disbelief=0.1, uncertainty=0.4, base_rate=0.5)
        op_b = Opinion(belief=0.6, disbelief=0.1, uncertainty=0.3, base_rate=0.5)
        fused = fuse_consensus(op_a, op_b)
        self.assertAlmostEqual(fused.belief + fused.disbelief + fused.uncertainty, 1.0)
        self.assertLess(fused.uncertainty, op_a.uncertainty)
        self.assertLess(fused.uncertainty, op_b.uncertainty)

    def test_evaluate_subjective_logic_pipeline(self):
        ev = EvidenceObject(
            evidence_id="ev1",
            type="auth.dkim.pass",
            category="authentication",
            raw_observation="dkim passed",
            interpretation="valid",
            conclusion="benign",
            source_component="verifier",
            detection_method="cryptographic",
            observed_at=datetime.now(timezone.utc).isoformat(),
            severity="informational",
            direction="legitimate",
            reliability=0.99,
            weight=2.0,
            uncertainty=0.05,
        )
        res = evaluate_subjective_logic([ev])
        self.assertGreater(res.disbelief, res.belief)
        self.assertLess(res.projected_probability, 0.5)


class InvestigationAndGraphTests(unittest.TestCase):
    @patch("services.investigation.graph_service.graph_nodes_collection.update_one", new_callable=AsyncMock)
    @patch("services.investigation.graph_service.graph_edges_collection.update_one", new_callable=AsyncMock)
    def test_index_graph_entities(self, mock_edge, mock_node):
        parsed = {
            "filename": "phish.eml",
            "headers": {"sender": ["attacker@evil.com"]},
            "attachments": [{"filename": "invoice.exe", "sha256": "feedbeef1234"}],
        }
        urls = {"all_urls": ["https://evil.com/login"]}
        relays = {"primary_origin": {"ip": "198.51.100.88"}}

        res = run_coro(index_email_graph_entities("email-001", parsed, urls, relays))
        self.assertGreaterEqual(res["nodes_indexed"], 4)
        self.assertGreaterEqual(res["edges_indexed"], 3)

    @patch("services.investigation.graph_service.graph_edges_collection.find")
    def test_campaign_correlation(self, mock_find):
        cursor = MagicMock()

        async def fake_iter():
            yield {"source": "email_peer-999", "target": "att_123", "relation": "HAS_ATTACHMENT"}

        cursor.__aiter__ = lambda self: fake_iter()
        mock_find.return_value = cursor

        parsed = {
            "attachments": [{"filename": "malware.bin", "sha256": "1234567890abcdef"}],
        }
        res = run_coro(corate := correlate_email_campaigns("email-curr", parsed, {}, {}))
        self.assertTrue(res["is_correlated"])
        self.assertIn("peer-999", res["related_email_ids"])
        self.assertIsNotNone(res["campaign_id"])

    def test_forensic_report_generation(self):
        investigation = {
            "_id": "inv-test-1",
            "status": "in_progress",
            "priority": "high",
            "notes": [{"content": "Suspicious payload analyzed"}],
            "audit_log": [],
        }
        email_record = {
            "_id": "email-test-1",
            "email": {"headers": {"subject": "Urgent wire request", "sender": ["cfo@fakecorp.com"]}},
            "risk_assessment": {"score": 85, "category": "critical"},
            "scoring_details": {"final_score": 85, "band": "Critical", "formula": "test"},
            "subjective_logic": {"projected_probability": 0.88},
            "relay_analysis": {"total_hops": 2, "primary_origin": {"ip": "203.0.113.1"}},
            "campaign_correlation": {"campaign_id": "camp_abc", "is_correlated": True},
            "evidence": [{"evidence_id": "ev-1", "category": "headers", "severity": "high"}],
        }
        report = generate_forensic_report(investigation, email_record)
        self.assertEqual(report["executive_summary"]["investigation_id"], "inv-test-1")
        self.assertEqual(report["executive_summary"]["threat_band"], "Critical")
        self.assertEqual(len(report["evidence_ledger"]), 1)
        self.assertEqual(report["transport_telemetry"]["primary_origin"]["ip"], "203.0.113.1")


class InvestigationEndpointTests(unittest.TestCase):
    @patch("api.v1.endpoints.investigations.emails_collection.find_one", new_callable=AsyncMock)
    @patch("api.v1.endpoints.investigations.investigations_collection.insert_one", new_callable=AsyncMock)
    def test_create_investigation(self, mock_insert, mock_email_find):
        mock_email_find.return_value = {
            "_id": "email-1",
            "filename": "sample.eml",
            "email": {"headers": {"subject": "Urgent Alert"}},
            "risk_assessment": {"score": 75},
        }
        current_user = {"id": "user-1", "email": "analyst@shield.local"}
        req = InvestigationCreateRequest(email_id="email-1", priority="high")
        res = run_coro(inv_endpoint.create_investigation(req, current_user=current_user))
        self.assertEqual(res["priority"], "high")
        self.assertEqual(res["user_id"], "user-1")
        self.assertIn("Forensic Case", res["title"])

    @patch("api.v1.endpoints.investigations.investigations_collection.find_one", new_callable=AsyncMock)
    @patch("api.v1.endpoints.investigations.investigations_collection.update_one", new_callable=AsyncMock)
    def test_add_note_to_investigation(self, mock_update, mock_find):
        mock_find.return_value = {"_id": "inv-1", "email_id": "email-1"}
        current_user = {"id": "user-1", "email": "analyst@shield.local"}
        req = InvestigationNoteRequest(content="Phishing kit identified on host.")
        res = run_coro(inv_endpoint.add_investigation_note("inv-1", req, current_user=current_user))
        self.assertEqual(res["content"], "Phishing kit identified on host.")
        self.assertEqual(mock_update.call_count, 1)


if __name__ == "__main__":
    unittest.main()
