"""
Unit tests validating Weights & Biases artifact registry audit checks.
"""

import unittest
from scanner.integrations.wandb_auditor import WandbArtifactAuditor
from scanner.rules.dangerous_symbols import RiskLevel


class TestWandbArtifactAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = WandbArtifactAuditor()

    def test_clean_safetensors_manifest(self):
        clean_manifest = {
            "contents": {
                "model.safetensors": {"digest": "sha256-abcdef123456", "size": 102400},
                "config.json": {"digest": "sha256-654321fedcba", "size": 512},
            },
            "metadata": {"framework": "safetensors", "verified": True},
        }
        findings = self.auditor.audit_manifest(clean_manifest, "entity/proj/model:v1")
        self.assertEqual(len(findings), 0)

    def test_legacy_pickle_flagged(self):
        legacy_manifest = {
            "contents": {
                "pytorch_model.bin": {"digest": "sha256-1111", "size": 5000},
            }
        }
        findings = self.auditor.audit_manifest(legacy_manifest, "entity/proj/legacy:v0")
        self.assertTrue(any(f.rule_id == "WANDB-LEGACY-DESERIALIZATION-ARTIFACT" for f in findings))

    def test_missing_digest_flagged(self):
        corrupt_manifest = {
            "contents": {
                "weights.safetensors": {"size": 5000},
            }
        }
        findings = self.auditor.audit_manifest(corrupt_manifest, "entity/proj/corrupt:v0")
        self.assertTrue(any(f.rule_id == "WANDB-MISSING-DIGEST-CHECKSUM" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.HIGH)


if __name__ == "__main__":
    unittest.main()
