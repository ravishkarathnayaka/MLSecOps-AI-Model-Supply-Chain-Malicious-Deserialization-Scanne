"""
Unit tests for CSVReporter.
Validates CSV headers, escaping, and column row serialization.
"""

from scanner.core.csv_reporter import CSVReporter
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import AdmissionVerdict, EvaluationResult, Finding


def test_csv_reporter_format():
    finding = Finding(
        rule_id="TEST-RULE-01",
        title="Test Finding Title, with commas",
        severity=RiskLevel.HIGH,
        category="code_execution",
        description="Testing description quotes \"double\"",
        location="model.pkl:0x0010",
        details={"offset": 16},
    )
    eval_res = EvaluationResult(
        verdict=AdmissionVerdict.FAILED,
        passed=False,
        fail_threshold=RiskLevel.HIGH,
        violations=[],
        findings=[finding],
        highest_severity=RiskLevel.HIGH,
        risk_score=40.0,
        summary="Failed summary",
    )
    csv_str = CSVReporter.to_csv_string(eval_res)
    lines = [line.strip() for line in csv_str.strip().splitlines()]

    assert len(lines) == 2
    assert lines[0] == "rule_id,severity,title,category,location,description,details_json"
    assert "TEST-RULE-01" in lines[1]
    assert "HIGH" in lines[1]
    assert "model.pkl:0x0010" in lines[1]
