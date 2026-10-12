"""
Unit tests for MLflowModelAuditor.
Validates MLmodel manifest auditing, custom code path flags, and loader module verification.
"""

from scanner.integrations.mlflow_auditor import MLflowModelAuditor
from scanner.rules.dangerous_symbols import RiskLevel


def test_mlflow_clean_model(tmp_path):
    auditor = MLflowModelAuditor()
    mlmodel_content = """
artifact_path: model
flavors:
  python_function:
    loader_module: mlflow.sklearn
    model_path: model.pkl
    python_version: 3.10.0
"""
    (tmp_path / "MLmodel").write_text(mlmodel_content)
    (tmp_path / "model.pkl").write_bytes(b"data")

    findings = auditor.audit_mlflow_directory(str(tmp_path))
    assert not any("MLFLOW" in f.rule_id for f in findings)


def test_mlflow_custom_code_path_flagged(tmp_path):
    auditor = MLflowModelAuditor()
    mlmodel_content = """
artifact_path: model
flavors:
  python_function:
    code: custom_hooks
    loader_module: mlflow.pyfunc
"""
    (tmp_path / "MLmodel").write_text(mlmodel_content)

    findings = auditor.audit_mlflow_directory(str(tmp_path))
    assert any(f.rule_id == "MLFLOW-CUSTOM-CODE-DIR-FLAGGED" for f in findings)
    assert any(f.severity == RiskLevel.HIGH for f in findings)


def test_mlflow_third_party_loader_module(tmp_path):
    auditor = MLflowModelAuditor()
    mlmodel_content = """
artifact_path: model
flavors:
  python_function:
    loader_module: malicious_package.loader
"""
    (tmp_path / "MLmodel").write_text(mlmodel_content)

    findings = auditor.audit_mlflow_directory(str(tmp_path))
    assert any(f.rule_id == "MLFLOW-THIRD-PARTY-LOADER-MODULE" for f in findings)
