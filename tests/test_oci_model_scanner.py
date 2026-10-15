"""
Unit tests validating OCI / ORAS container registry model manifest security analysis.
"""

import unittest
from scanner.integrations.oci_model_scanner import OCIModelScanner
from scanner.rules.dangerous_symbols import RiskLevel


class TestOCIModelScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = OCIModelScanner()

    def test_clean_oci_manifest(self):
        clean_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": [
                {
                    "mediaType": "application/vnd.safetensors.model.v1",
                    "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "size": 1024,
                }
            ],
        }
        findings = self.scanner.scan_manifest(clean_manifest, "registry.io/llm:v1")
        self.assertEqual(len(findings), 0)

    def test_prohibited_pickle_layer_flagged(self):
        pickle_manifest = {
            "schemaVersion": 2,
            "layers": [
                {
                    "mediaType": "application/vnd.pytorch.pickle.layer.v1",
                    "digest": "sha256:1111222233334444555566667777888899990000aaaa",
                    "size": 5000,
                }
            ],
        }
        findings = self.scanner.scan_manifest(pickle_manifest, "registry.io/trojan:v1")
        self.assertTrue(any(f.rule_id == "OCI-PROHIBITED-LAYER-MEDIA-TYPE" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    def test_invalid_digest_flagged(self):
        bad_digest_manifest = {
            "schemaVersion": 2,
            "layers": [
                {"mediaType": "application/vnd.onnx.model", "digest": "md5:12345", "size": 100}
            ],
        }
        findings = self.scanner.scan_manifest(bad_digest_manifest, "registry.io/bad-digest:v1")
        self.assertTrue(any(f.rule_id == "OCI-INVALID-LAYER-DIGEST" for f in findings))


if __name__ == "__main__":
    unittest.main()
