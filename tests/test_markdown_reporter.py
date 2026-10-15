"""
Unit tests validating Markdown executive summary report formatting.
"""

import unittest
from scanner.core.markdown_reporter import MarkdownReporter
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import AdmissionVerdict, EvaluationResult, PolicyViolation


class TestMarkdownReporter(unittest.TestCase):
    def test_clean_evaluation_report(self):
        eval_result = EvaluationResult(
            verdict=AdmissionVerdict.PASSED,
            passed=True,
            fail_threshold=RiskLevel.HIGH,
            violations=[],
            findings=[],
            highest_severity=None,
            risk_score=0.0,
            summary="All 1 files passed static inspection.",
        )
        md = MarkdownReporter.generate_report(eval_result, ["model.safetensors"])
        self.assertIn("PASSED", md)
        self.assertIn("Zero security vulnerabilities", md)

    def test_failed_evaluation_report(self):
        f = Finding(
            rule_id="ARBITRARY-CODE-EXECUTION-REDUCE",
            title="Pickle Code Execution",
            severity=RiskLevel.CRITICAL,
            description="Malicious opcode payload",
            location="trojan.pkl",
            category="deserialization_injection",
        )
        viol = PolicyViolation(finding=f, threshold=RiskLevel.HIGH, message="Violation")
        eval_result = EvaluationResult(
            verdict=AdmissionVerdict.FAILED,
            passed=False,
            fail_threshold=RiskLevel.HIGH,
            violations=[viol],
            findings=[f],
            highest_severity=RiskLevel.CRITICAL,
            risk_score=95.0,
            summary="Found 1 critical violations.",
        )
        md = MarkdownReporter.generate_report(eval_result, ["trojan.pkl"])
        self.assertIn("FAILED - QUARANTINED", md)
        self.assertIn("ARBITRARY-CODE-EXECUTION-REDUCE", md)
        self.assertIn("95.0", md)


if __name__ == "__main__":
    unittest.main()
