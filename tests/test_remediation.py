"""
Unit tests validating automated security remediation advice generation.
"""

import unittest
from scanner.core.remediation import RemediationAdvisor
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class TestRemediationAdvisor(unittest.TestCase):
    def test_arbitrary_code_remediation(self):
        finding = Finding(
            rule_id="ARBITRARY-CODE-EXECUTION-REDUCE",
            title="Pickle Code Execution",
            severity=RiskLevel.CRITICAL,
            description="Malicious opcode payload",
            location="model.pkl",
        )
        RemediationAdvisor.attach_remediations([finding])
        self.assertIn("remediation", finding.details)
        remediation = finding.details["remediation"]
        self.assertIn("Safetensors", remediation["title"])
        self.assertIn("save_file", remediation["action"])

    def test_onnx_remediation(self):
        finding = Finding(
            rule_id="ONNX-CUSTOM-OPERATOR-FLAGGED",
            title="Custom ONNX Op",
            severity=RiskLevel.HIGH,
            description="Custom operator in graph",
            location="graph.onnx",
        )
        guide = RemediationAdvisor.get_remediation_for_finding(finding)
        self.assertIn("opset", guide["action"])

    def test_fallback_remediation(self):
        finding = Finding(
            rule_id="UNKNOWN-ANOMALY",
            title="Unknown Anomaly",
            severity=RiskLevel.LOW,
            description="Something minor",
            location="file",
        )
        guide = RemediationAdvisor.get_remediation_for_finding(finding)
        self.assertIn("Quarantine", guide["action"])


if __name__ == "__main__":
    unittest.main()
