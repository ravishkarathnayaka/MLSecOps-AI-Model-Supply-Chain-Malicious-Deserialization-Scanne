"""
Unit tests validating PaddlePaddle model and parameter static security analysis.
"""

import unittest
from scanner.analyzers.paddle_analyzer import PaddlePaddleAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


class TestPaddlePaddleAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PaddlePaddleAnalyzer()

    def test_clean_paddle_model(self):
        # Benign mock protobuf graph with Conv2D and ElementwiseAdd
        clean_model = b"\x08\x01\x12\x06conv2d\x1a\x04data\x22\x04conv\x12\x0eElementwiseAdd"
        findings = self.analyzer.analyze_bytes(clean_model, "inference.pdmodel")
        self.assertEqual(len(findings), 0)

    def test_py_func_operator_flagged(self):
        malicious_model = b"\x08\x01\x12\x07py_func\x1a\x08callback"
        findings = self.analyzer.analyze_bytes(malicious_model, "trojan.pdmodel")
        self.assertTrue(any(f.rule_id == "PADDLE-UNSAFE-OP-PY-FUNC" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    def test_embedded_pickle_in_params_flagged(self):
        malicious_params = b"\x00\x00\x00\x01\x80\x04cos\nsystem\n(X\x06\x00\x00\x00whoami\x85R."
        findings = self.analyzer.analyze_bytes(malicious_params, "model.pdparams")
        self.assertTrue(any(f.rule_id == "PADDLE-EMBEDDED-PICKLE-INJECTION" for f in findings))

    def test_path_traversal_flagged(self):
        traversal_bytes = b"\x08\x01\x12\x0a../../etc/passwd"
        findings = self.analyzer.analyze_bytes(traversal_bytes, "model.pdmodel")
        self.assertTrue(any(f.rule_id == "PADDLE-PATH-TRAVERSAL-DETECTED" for f in findings))


if __name__ == "__main__":
    unittest.main()
