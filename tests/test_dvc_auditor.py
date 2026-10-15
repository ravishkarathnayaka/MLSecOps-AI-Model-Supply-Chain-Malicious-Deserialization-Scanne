"""
Unit tests validating Data Version Control (DVC) stage and model pointer security audits.
"""

import unittest
from scanner.integrations.dvc_auditor import DVCPipelineAuditor
from scanner.rules.dangerous_symbols import RiskLevel


class TestDVCPipelineAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = DVCPipelineAuditor()

    def test_clean_safetensors_dvc(self):
        clean_yaml = """
outs:
  - path: model.safetensors
    md5: 8f4e2b10a9c8d7e6f5a4b3c2d1e0f9a8
    size: 409600
"""
        findings = self.auditor.audit_dvc_file(clean_yaml, "model.safetensors.dvc")
        self.assertEqual(len(findings), 0)

    def test_legacy_pickle_output_flagged(self):
        pickle_yaml = """
outs:
  - path: weights.pt
    md5: 1234567890abcdef1234567890abcdef
"""
        findings = self.auditor.audit_dvc_file(pickle_yaml, "weights.pt.dvc")
        self.assertTrue(any(f.rule_id == "DVC-LEGACY-PICKLE-OUTPUT" for f in findings))

    def test_missing_hash_flagged(self):
        untracked_yaml = """
outs:
  - path: unverified_model.safetensors
"""
        findings = self.auditor.audit_dvc_file(untracked_yaml, "unverified.dvc")
        self.assertTrue(any(f.rule_id == "DVC-MISSING-OUTPUT-HASH" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.HIGH)


if __name__ == "__main__":
    unittest.main()
