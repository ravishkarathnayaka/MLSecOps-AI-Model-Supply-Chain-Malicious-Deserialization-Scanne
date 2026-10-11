"""
Unit tests for HTMLReporter.
Validates HTML rendering, structure, and HTML entity escaping.
"""

from scanner.core.html_reporter import HTMLReporter
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import AdmissionVerdict, EvaluationResult, Finding


def test_html_reporter_clean_run():
    eval_res = EvaluationResult(
        verdict=AdmissionVerdict.PASSED,
        passed=True,
        fail_threshold=RiskLevel.HIGH,
        violations=[],
        findings=[],
        highest_severity=None,
        risk_score=0.0,
        summary="Clean run",
    )
    html_output = HTMLReporter.generate_html(eval_res, ["models/safe.pt"])
    assert "<!DOCTYPE html>" in html_output
    assert "PASSED" in html_output
    assert "No security findings detected" in html_output


def test_html_reporter_with_findings_and_escaping():
    finding = Finding(
        rule_id="DANGEROUS-GLOBAL-CRITICAL",
        title="<script>alert(1)</script> os.system injection",
        severity=RiskLevel.CRITICAL,
        category="code_execution",
        description="Executes arbitrary command",
        location="model.pkl::<script>",
    )
    eval_res = EvaluationResult(
        verdict=AdmissionVerdict.FAILED,
        passed=False,
        fail_threshold=RiskLevel.HIGH,
        violations=[],
        findings=[finding],
        highest_severity=RiskLevel.CRITICAL,
        risk_score=100.0,
        summary="Failed run",
    )
    html_output = HTMLReporter.generate_html(eval_res, ["model.pkl"])
    assert "FAILED" in html_output
    assert "CRITICAL" in html_output
    assert "&lt;script&gt;" in html_output
    assert "<script>alert(1)</script>" not in html_output  # Ensure XSS escaped
