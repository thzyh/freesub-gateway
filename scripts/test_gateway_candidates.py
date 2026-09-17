#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gateway feed regression tests; no network or sing-box runtime required."""

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone

import main_v2 as mv


class GatewayCandidateTests(unittest.TestCase):
    def setUp(self):
        self.old_output = mv.OUTPUT_DIR
        self.old_path = mv.GATEWAY_CANDIDATES_PATH
        self.old_sources = mv.SOURCE_MAP
        self.tmp = tempfile.TemporaryDirectory()
        mv.OUTPUT_DIR = self.tmp.name
        mv.GATEWAY_CANDIDATES_PATH = os.path.join(self.tmp.name, "gateway-candidates.json")
        self.checked_at = datetime.now(timezone.utc).isoformat()

    def tearDown(self):
        mv.OUTPUT_DIR = self.old_output
        mv.GATEWAY_CANDIDATES_PATH = self.old_path
        mv.SOURCE_MAP = self.old_sources
        self.tmp.cleanup()

    def test_feed_contains_provenance_and_stable_id(self):
        outbound = {
            "type": "vless",
            "server": "198.51.100.10",
            "server_port": 443,
            "uuid": "00000000-0000-4000-8000-000000000001",
        }
        item = {
            "proto": "vless",
            "country": "IN",
            "exit_ip": "203.0.113.10",
            "net_type": "residential",
            "asn": 64500,
            "isp": "Example ISP",
            "latency_ms": 120,
            "speed_bps": 500000,
            "confidence": 80,
            "fraud_score": 12,
            "gateway_quality": {
                "source": "ping0",
                "risk_score": 12,
                "native_ip": True,
                "native_label": "原生 IP",
                "scenario_stars": {
                    "tiktok": 5,
                    "cross_border_ecommerce": 4,
                    "social_media": 5,
                    "ai": 4,
                },
                "checked_at": self.checked_at,
            },
            "mitm_risk": False,
            "is_stalled": False,
            "tested_at": "2026-09-16T00:00:00+00:00",
            "upstream_sources": ["https://source.example/a", "https://source.example/b"],
            "outbound": outbound,
        }
        count = mv.export_gateway_candidates([item])
        self.assertEqual(count, 1)
        with open(mv.GATEWAY_CANDIDATES_PATH, encoding="utf-8") as stream:
            payload = json.load(stream)
        self.assertEqual(payload["schema_version"], 2)
        candidate = payload["candidates"][0]
        self.assertEqual(candidate["protocol"], "vless")
        self.assertEqual(candidate["upstream_sources"], [
            "https://source.example/a", "https://source.example/b"
        ])
        self.assertRegex(candidate["candidate_id"], r"^fs-[0-9a-f]{24}$")
        self.assertEqual(candidate["candidate_id"], mv.gateway_candidate_id(item))
        self.assertEqual(candidate["risk_score"], 12)
        self.assertTrue(candidate["quality"]["native_ip"])
        self.assertEqual(candidate["quality"]["scenario_stars"]["cross_border_ecommerce"], 4)
        self.assertEqual(candidate["risk_signals"]["fraud_score"], 12)

    def test_feed_rejects_missing_or_unqualified_ping0_evidence(self):
        base = {
            "proto": "vless", "country": "TW", "exit_ip": "122.118.150.43",
            "net_type": "residential", "latency_ms": 20, "speed_bps": 200000,
            "confidence": 90, "fraud_score": 0, "ip_api_proxy": False,
            "ip_api_hosting": False, "mitm_risk": False, "is_stalled": False,
            "outbound": {"type": "vless", "server": "example.com", "server_port": 443},
        }
        qualified = {
            "source": "ping0", "risk_score": 9, "native_ip": True,
            "native_label": "原生 IP", "checked_at": self.checked_at,
            "scenario_stars": {
                "tiktok": 5, "cross_border_ecommerce": 5,
                "social_media": 5, "ai": 5,
            },
        }
        rejected = [
            dict(base),
            dict(base, gateway_quality=dict(qualified, risk_score=16)),
            dict(base, gateway_quality=dict(qualified, native_ip=False, native_label="广播 IP")),
            dict(base, gateway_quality=dict(qualified, scenario_stars=dict(qualified["scenario_stars"], ai=3))),
            dict(base, gateway_quality=dict(qualified), net_type="datacenter"),
            dict(base, gateway_quality=dict(qualified), ip_api_proxy=True),
            dict(base, gateway_quality=dict(qualified), ip_api_hosting=True),
        ]
        self.assertEqual(mv.export_gateway_candidates(rejected), 0)

        self.assertEqual(mv.export_gateway_candidates([dict(base, gateway_quality=qualified)]), 1)

    def test_feed_excludes_unsupported_protocols_and_marks_risk(self):
        base = {
            "country": "TR", "exit_ip": "203.0.113.11", "net_type": "unknown",
            "latency_ms": 1, "speed_bps": 0, "confidence": 30,
            "mitm_risk": True, "is_stalled": False, "outbound": {
                "type": "hysteria2", "server": "198.51.100.11", "server_port": 443,
            },
        }
        self.assertEqual(mv.export_gateway_candidates([dict(base, proto="hysteria2")]), 0)
        vless = dict(base, proto="vless", outbound=dict(base["outbound"], type="vless"))
        self.assertEqual(mv.export_gateway_candidates([vless]), 0)
        with open(mv.GATEWAY_CANDIDATES_PATH, encoding="utf-8") as stream:
            payload = json.load(stream)
        self.assertEqual(payload["candidates"], [])

        invalid_country = dict(vless, country="OTHER")
        self.assertEqual(mv.export_gateway_candidates([invalid_country]), 0)

    def test_proxy_signal_excludes_datacenter_candidate(self):
        item = {
            "proto": "shadowsocks",
            "country": "US",
            "exit_ip": "37.19.198.244",
            "net_type": "residential",
            "asn": 212238,
            "isp": "Datacamp",
            "latency_ms": 60,
            "speed_bps": 6885561,
            "confidence": 90,
            "fraud_score": 67,
            "ip_api_proxy": True,
            "ip_api_hosting": True,
            "mitm_risk": False,
            "is_stalled": False,
            "outbound": {
                "type": "shadowsocks",
                "server": "37.19.198.244",
                "server_port": 443,
                "method": "aes-128-gcm",
                "password": "shadowsocks",
            },
        }

        self.assertEqual(mv.export_gateway_candidates([item]), 0)

    def test_unknown_fraud_does_not_turn_confidence_into_low_risk(self):
        item = {
            "net_type": "residential",
            "confidence": 90,
            "fraud_score": -1,
            "ip_api_proxy": False,
            "ip_api_hosting": True,
            "mitm_risk": False,
            "is_stalled": False,
        }

        self.assertFalse(mv.gateway_quality_is_eligible(item))

    def test_feed_merges_duplicate_stable_ids_and_provenance(self):
        outbound = {
            "type": "trojan", "server": "198.51.100.20", "server_port": 443,
            "password": "test-password",
        }
        common = {
            "proto": "trojan", "country": "US", "exit_ip": "203.0.113.20",
            "net_type": "residential", "asn": 64500, "isp": "Example ISP",
            "confidence": 80, "fraud_score": 10, "mitm_risk": False,
            "is_stalled": False, "outbound": outbound,
            "gateway_quality": {
                "source": "ping0", "risk_score": 10, "native_ip": True,
                "native_label": "原生 IP", "checked_at": self.checked_at,
                "scenario_stars": {
                    "tiktok": 5, "cross_border_ecommerce": 5,
                    "social_media": 5, "ai": 5,
                },
            },
        }
        slower = dict(common, latency_ms=300, speed_bps=100000,
                      upstream_sources=["https://source.example/a"])
        faster = dict(common, latency_ms=100, speed_bps=200000,
                      upstream_sources=["https://source.example/b"])

        self.assertEqual(mv.export_gateway_candidates([slower, faster]), 1)
        with open(mv.GATEWAY_CANDIDATES_PATH, encoding="utf-8") as stream:
            candidates = json.load(stream)["candidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["latency_ms"], 100)
        self.assertEqual(candidates[0]["upstream_sources"], [
            "https://source.example/a", "https://source.example/b"
        ])

    def test_parse_ping0_quality_html(self):
        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "ping0-qualified.html")
        with open(fixture, encoding="utf-8") as stream:
            quality = mv.parse_ping0_quality_html(
                stream.read(), "122.118.150.43", datetime(2026, 9, 17, tzinfo=timezone.utc)
            )
        self.assertEqual(quality["risk_score"], 9)
        self.assertTrue(quality["native_ip"])
        self.assertEqual(quality["scenario_stars"], {
            "tiktok": 5,
            "cross_border_ecommerce": 5,
            "social_media": 5,
            "ai": 5,
        })

    def test_parse_ping0_quality_rejects_captcha_and_wrong_ip(self):
        self.assertIsNone(mv.parse_ping0_quality_html('<div class="cf-turnstile"></div>', "122.118.150.43"))
        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "ping0-qualified.html")
        with open(fixture, encoding="utf-8") as stream:
            self.assertIsNone(mv.parse_ping0_quality_html(stream.read(), "111.246.9.5"))


if __name__ == "__main__":
    unittest.main()
