"""
Unit tests validating ClearML model repository security verification.
"""

import unittest
from scanner.integrations.clearml_verifier import ClearMLModelVerifier
from scanner.rules.dangerous_symbols import RiskLevel


class TestClearMLModelVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = ClearMLModelVerifier()

    def test_clean_model_record(self):
        record = {
            "id": "mdl-12345",
            "name": "resnet50_v2",
            "uri": "s3://ml-models/resnet50.onnx",
            "framework": "onnx",
            "tags": ["production", "approved"],
        }
        findings = self.verifier.verify_model_record(record)
        self.assertEqual(len(findings), 0)

    def test_insecure_http_uri_flagged(self):
        record = {
            "id": "mdl-67890",
            "uri": "http://insecure-host:9000/weights.pt",
            "framework": "pytorch",
        }
        findings = self.verifier.verify_model_record(record)
        self.assertTrue(any(f.rule_id == "CLEARML-INSECURE-HTTP-STORAGE-URI" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.HIGH)

    def test_quarantined_tag_flagged(self):
        record = {
            "id": "mdl-trojan",
            "uri": "https://secure-repo/trojan.pt",
            "tags": ["quarantined"],
        }
        findings = self.verifier.verify_model_record(record)
        self.assertTrue(any(f.rule_id == "CLEARML-TAGGED-QUARANTINED" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)


if __name__ == "__main__":
    unittest.main()
