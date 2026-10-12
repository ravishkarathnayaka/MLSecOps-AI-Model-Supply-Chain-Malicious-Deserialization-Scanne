"""
Unit tests for CVSSScoringEngine.
Validates CVSS v3.1 score calculations, vector string formatting, and composite model risk aggregation.
"""

from scanner.core.scoring import CVSSScoringEngine
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding


def test_cvss_code_execution_scoring():
    finding = Finding(
        rule_id="ARBITRARY-CODE-EXECUTION-REDUCE",
        title="REDUCE Opcode Execution",
        severity=RiskLevel.CRITICAL,
        category="code_execution",
        description="Arbitrary execution",
        location="model.pkl",
    )
    result = CVSSScoringEngine.score_finding(finding)
    assert result.base_score == 9.8
    assert result.severity_label == "CRITICAL"
    assert "AV:N/AC:L" in result.vector_string


def test_cvss_network_exfiltration_scoring():
    finding = Finding(
        rule_id="DANGEROUS-GLOBAL-SOCKET",
        title="Raw Socket Creation",
        severity=RiskLevel.CRITICAL,
        category="network_exfiltration",
        description="Data exfiltration channel",
        location="model.pt",
    )
    result = CVSSScoringEngine.score_finding(finding)
    assert result.base_score == 8.6
    assert result.severity_label == "HIGH"


def test_cvss_aggregate_scoring():
    clean_score = CVSSScoringEngine.aggregate_model_score([])
    assert clean_score == 0.0

    finding_low = Finding(
        rule_id="TEST-LOW",
        title="Low Finding",
        severity=RiskLevel.LOW,
        category="general",
        description="Low",
        location="model.safetensors",
    )
    score = CVSSScoringEngine.aggregate_model_score([finding_low])
    assert score == 3.1
