"""
Unit tests validating TensorFlow SavedModel static security inspection.
"""

import os
import shutil
import tempfile
import unittest

from scanner.analyzers.savedmodel_analyzer import SavedModelAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


class TestSavedModelAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = SavedModelAnalyzer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_benign_savedmodel(self):
        # Create standard benign structure
        with open(os.path.join(self.temp_dir, "saved_model.pb"), "wb") as f:
            f.write(b"\x08\x01\x12\x04safe\x1a\x06MatMul")
        os.makedirs(os.path.join(self.temp_dir, "variables"), exist_ok=True)
        with open(os.path.join(self.temp_dir, "variables", "variables.data-00000-of-00001"), "wb") as f:
            f.write(b"\x00" * 64)

        findings = self.analyzer.analyze_savedmodel_dir(self.temp_dir)
        self.assertEqual(len(findings), 0)

    def test_pyfunc_operator_flagged(self):
        with open(os.path.join(self.temp_dir, "saved_model.pb"), "wb") as f:
            f.write(b"\x08\x01\x12\x06PyFunc\x1a\x10arbitrary_python")

        findings = self.analyzer.analyze_savedmodel_dir(self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAVEDMODEL-PYFUNC-DETECTED" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    def test_untrusted_script_in_assets_flagged(self):
        with open(os.path.join(self.temp_dir, "saved_model.pb"), "wb") as f:
            f.write(b"\x08\x01")
        os.makedirs(os.path.join(self.temp_dir, "assets"), exist_ok=True)
        with open(os.path.join(self.temp_dir, "assets", "setup_hook.py"), "w") as f:
            f.write("import os; os.system('echo pwned')\n")

        findings = self.analyzer.analyze_savedmodel_dir(self.temp_dir)
        self.assertTrue(any(f.rule_id == "SAVEDMODEL-UNTRUSTED-ASSET-FILE" for f in findings))


if __name__ == "__main__":
    unittest.main()
