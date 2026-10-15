"""
Unit tests validating JUnit XML test report generation from scan results.
"""

import unittest
from scanner.core.junit_reporter import JUnitReporter
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import AdmissionVerdict, EvaluationResult, PolicyViolation


class TestJUnitReporter(unittest.TestCase):
    def test_clean_model_junit_xml(self):
        eval_result = EvaluationResult(
            verdict=AdmissionVerdict.PASSED,
            passed=True,
            fail_threshold=RiskLevel.HIGH,
            violations=[],
            findings=[],
            highest_severity=None,
            risk_score=0.0,
            summary="Clean",
        )
        xml = JUnitReporter.generate_junit_xml(eval_result, ["safe_model.safetensors"])
        self.assertIn('<testsuite name="ModelSecurityInspection" tests="1" failures="0"', xml)
        self.assertIn('<testcase classname="mlsecops.model_inspection" name="safe_model.safetensors"', xml)
        self.assertNotIn("<failure", xml)

    def test_trojan_model_junit_xml(self):
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
            summary="Failed",
        )
        xml = JUnitReporter.generate_junit_xml(eval_result, ["trojan.pkl"])
        self.assertIn('<testsuite name="ModelSecurityInspection" tests="1" failures="1"', xml)
        self.assertIn('<failure message="ARBITRARY-CODE-EXECUTION-REDUCE: Malicious opcode payload" type="CRITICAL">', xml)


if __name__ == "__main__":
    unittest.main()
