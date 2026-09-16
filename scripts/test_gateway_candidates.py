#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gateway feed regression tests; no network or sing-box runtime required."""

import json
import os
import tempfile
import unittest

import main_v2 as mv


class GatewayCandidateTests(unittest.TestCase):
    def setUp(self):
        self.old_output = mv.OUTPUT_DIR
        self.old_path = mv.GATEWAY_CANDIDATES_PATH
        self.old_sources = mv.SOURCE_MAP
        self.tmp = tempfile.TemporaryDirectory()
        mv.OUTPUT_DIR = self.tmp.name
        mv.GATEWAY_CANDIDATES_PATH = os.path.join(self.tmp.name, "gateway-candidates.json")

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
            "net_type": "datacenter",
            "asn": 64500,
            "isp": "Example ISP",
            "latency_ms": 120,
            "speed_bps": 500000,
            "confidence": 80,
            "fraud_score": 12,
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
        self.assertEqual(payload["schema_version"], 1)
        candidate = payload["candidates"][0]
        self.assertEqual(candidate["protocol"], "vless")
        self.assertEqual(candidate["upstream_sources"], [
            "https://source.example/a", "https://source.example/b"
        ])
        self.assertRegex(candidate["candidate_id"], r"^fs-[0-9a-f]{24}$")
        self.assertEqual(candidate["candidate_id"], mv.gateway_candidate_id(item))
        self.assertEqual(candidate["risk_score"], 20)

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
        self.assertEqual(mv.export_gateway_candidates([vless]), 1)
        with open(mv.GATEWAY_CANDIDATES_PATH, encoding="utf-8") as stream:
            payload = json.load(stream)
        self.assertEqual(payload["candidates"][0]["risk_score"], 100)

        invalid_country = dict(vless, country="OTHER")
        self.assertEqual(mv.export_gateway_candidates([invalid_country]), 0)

    def test_feed_merges_duplicate_stable_ids_and_provenance(self):
        outbound = {
            "type": "trojan", "server": "198.51.100.20", "server_port": 443,
            "password": "test-password",
        }
        common = {
            "proto": "trojan", "country": "US", "exit_ip": "203.0.113.20",
            "net_type": "datacenter", "asn": 64500, "isp": "Example ISP",
            "confidence": 80, "fraud_score": 10, "mitm_risk": False,
            "is_stalled": False, "outbound": outbound,
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


if __name__ == "__main__":
    unittest.main()
