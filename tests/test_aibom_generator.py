"""
Unit tests for CycloneDXAIBOMGenerator.
Validates CycloneDX v1.5 schema structure, machine-learning-model component type, and findings mapping.
"""

from scanner.provenance.aibom_generator import CycloneDXAIBOMGenerator
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import AdmissionVerdict, EvaluationResult, Finding


def test_cyclonedx_aibom_schema(tmp_path):
    model_file = tmp_path / "model.safetensors"
    model_file.write_bytes(b"dummy weights data 12345678")

    bom = CycloneDXAIBOMGenerator.generate_bom(str(model_file), model_name="MyTransformer")

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["metadata"]["component"]["type"] == "machine-learning-model"
    assert bom["metadata"]["component"]["name"] == "MyTransformer"
    hashes = bom["metadata"]["component"]["hashes"]
    assert any(h["alg"] == "SHA-256" for h in hashes)


def test_cyclonedx_aibom_vulnerabilities_mapping(tmp_path):
    model_file = tmp_path / "trojan.pkl"
    model_file.write_bytes(b"payload")

    finding = Finding(
        rule_id="ARBITRARY-CODE-EXECUTION-REDUCE",
        title="Injected REDUCE Opcode",
        severity=RiskLevel.CRITICAL,
        category="code_execution",
        description="Arbitrary code execution on deserialize",
        location=str(model_file),
    )
    eval_res = EvaluationResult(
        verdict=AdmissionVerdict.FAILED,
        passed=False,
        fail_threshold=RiskLevel.HIGH,
        violations=[],
        findings=[finding],
        highest_severity=RiskLevel.CRITICAL,
        risk_score=100.0,
        summary="Failed",
    )

    bom = CycloneDXAIBOMGenerator.generate_bom(str(model_file), evaluation=eval_res)
    assert len(bom["vulnerabilities"]) == 1
    assert bom["vulnerabilities"][0]["id"] == "ARBITRARY-CODE-EXECUTION-REDUCE"
    assert bom["vulnerabilities"][0]["ratings"][0]["severity"] == "critical"
