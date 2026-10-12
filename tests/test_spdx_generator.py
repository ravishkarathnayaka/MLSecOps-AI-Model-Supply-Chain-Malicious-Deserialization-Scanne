"""
Unit tests for SPDXAIBOMGenerator.
Validates SPDX-2.3 format, checksums, and review annotations for AI model packages.
"""

from scanner.provenance.spdx_generator import SPDXAIBOMGenerator
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import AdmissionVerdict, EvaluationResult, Finding


def test_spdx_generator_structure(tmp_path):
    model_file = tmp_path / "model.onnx"
    model_file.write_bytes(b"dummy onnx protobuf")

    spdx = SPDXAIBOMGenerator.generate_spdx(str(model_file), license_id="Apache-2.0")

    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert len(spdx["packages"]) == 1
    pkg = spdx["packages"][0]
    assert pkg["name"] == "model.onnx"
    assert pkg["licenseConcluded"] == "Apache-2.0"
    assert any(c["algorithm"] == "SHA256" for c in pkg["checksums"])


def test_spdx_generator_annotations(tmp_path):
    model_file = tmp_path / "model.pt"
    model_file.write_bytes(b"data")

    finding = Finding(
        rule_id="PYTORCH-ZIP-SLIP-TRAVERSAL",
        title="Zip Slip Traversal",
        severity=RiskLevel.CRITICAL,
        category="traversal",
        description="Path traversal",
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

    spdx = SPDXAIBOMGenerator.generate_spdx(str(model_file), evaluation=eval_res)
    assert len(spdx["annotations"]) == 1
    assert "PYTORCH-ZIP-SLIP-TRAVERSAL" in spdx["annotations"][0]["comment"]
