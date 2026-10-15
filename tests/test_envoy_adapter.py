"""
Unit tests validating Envoy external authorization (ext_authz) filter adapter.
"""

import json
import unittest
from admission_gate.envoy_adapter import EnvoyExtAuthzAdapter


class TestEnvoyExtAuthzAdapter(unittest.TestCase):
    def setUp(self):
        def mock_evaluator(model_path: str):
            if "trojan" in model_path:
                return False, "Malicious pickle payload detected"
            return True, "Clean model"

        self.adapter = EnvoyExtAuthzAdapter(admission_evaluator_callable=mock_evaluator)

    def test_pass_through_no_model(self):
        resp = self.adapter.handle_check("/v1/models", {})
        self.assertTrue(resp.allowed)
        self.assertEqual(resp.http_status, 200)

    def test_admitted_model_header(self):
        resp = self.adapter.handle_check(
            "/v1/models/load",
            {"x-model-path": "/models/safe.safetensors"},
        )
        self.assertTrue(resp.allowed)
        self.assertEqual(resp.http_status, 200)
        self.assertEqual(resp.headers.get("x-mlsecops-verdict"), "admitted")

    def test_rejected_trojan_model_body(self):
        body = json.dumps({"model_path": "/models/trojan_print.pkl"}).encode("utf-8")
        resp = self.adapter.handle_check("/v1/models/load", {}, request_body=body)
        self.assertFalse(resp.allowed)
        self.assertEqual(resp.http_status, 403)
        self.assertEqual(resp.headers.get("x-mlsecops-verdict"), "rejected")
        self.assertIn("Malicious pickle payload", resp.body)


if __name__ == "__main__":
    unittest.main()
