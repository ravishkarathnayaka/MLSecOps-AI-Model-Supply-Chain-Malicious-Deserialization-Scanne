"""
Unit tests validating NVIDIA TensorRT engine plan static security inspection.
"""

import unittest
from scanner.analyzers.tensorrt_analyzer import TensorRTPlanAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


class TestTensorRTPlanAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = TensorRTPlanAnalyzer()

    def test_clean_tensorrt_plan(self):
        # Valid TRTE magic with standard internal layer metadata
        clean_bytes = b"TRTE\x00\x08\x00\x00\x00\x10\x00\x00Conv_1_output"
        findings = self.analyzer.analyze_bytes(clean_bytes, "model.plan")
        self.assertEqual(len(findings), 0)

    def test_truncated_plan_flagged(self):
        findings = self.analyzer.analyze_bytes(b"TR", "corrupt.plan")
        self.assertTrue(any(f.rule_id == "TENSORRT-FILE-TRUNCATED" for f in findings))

    def test_invalid_magic_flagged(self):
        findings = self.analyzer.analyze_bytes(b"INVALID_MAGIC_HEADER_BYTES", "bad.plan")
        self.assertTrue(any(f.rule_id == "TENSORRT-INVALID-MAGIC-HEADER" for f in findings))

    def test_external_plugin_library_flagged(self):
        trojan_plan = b"TRTE\x00\x08\x00\x00libplugin_exploit.so\x00"
        findings = self.analyzer.analyze_bytes(trojan_plan, "trojan.plan")
        self.assertTrue(any(f.rule_id == "TENSORRT-CUSTOM-PLUGIN-OR-LIB" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.HIGH)


if __name__ == "__main__":
    unittest.main()
