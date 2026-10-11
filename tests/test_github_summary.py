"""
Unit tests for GitHubStepSummaryReporter.
Validates GitHub Actions job summary Markdown table generation.
"""

from scanner.core.github_summary import GitHubStepSummaryReporter
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import AdmissionVerdict, EvaluationResult, Finding


def test_github_step_summary_clean():
    eval_res = EvaluationResult(
        verdict=AdmissionVerdict.PASSED,
        passed=True,
        fail_threshold=RiskLevel.HIGH,
        violations=[],
        findings=[],
        highest_severity=None,
        risk_score=0.0,
        summary="All clean",
    )
    md = GitHubStepSummaryReporter.render_markdown(eval_res, ["models/safe.onnx"])
    assert "### :white_check_mark: MLSecOps Gate: PASSED" in md
    assert ":sparkles: **CLEAN**" in md


def test_github_step_summary_violations():
    finding = Finding(
        rule_id="DANGEROUS-GLOBAL-CRITICAL",
        title="Command Execution Injection",
        severity=RiskLevel.CRITICAL,
        category="code_execution",
        description="Arbitrary code execution",
        location="model.pkl:0x0020",
    )
    eval_res = EvaluationResult(
        verdict=AdmissionVerdict.FAILED,
        passed=False,
        fail_threshold=RiskLevel.HIGH,
        violations=[],
        findings=[finding],
        highest_severity=RiskLevel.CRITICAL,
        risk_score=100.0,
        summary="Blocked model",
    )
    md = GitHubStepSummaryReporter.render_markdown(eval_res, ["model.pkl"])
    assert "### :no_entry: MLSecOps Gate: BLOCKED" in md
    assert ":red_circle: CRITICAL" in md
    assert "DANGEROUS-GLOBAL-CRITICAL" in md
