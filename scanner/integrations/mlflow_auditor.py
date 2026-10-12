"""
MLflow Model Registry Static Security Auditor.
Inspects MLflow directory packaging, 'MLmodel' YAML descriptor files,
custom python_function code loader scripts, and serialized flavor weights.
"""

import os
from typing import Any, Dict, List, Optional
import yaml

from scanner.core.engine import ModelScanEngine
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding


class MLflowModelAuditor:
    """Audits MLflow model directories and MLmodel metadata manifests."""

    def __init__(self, engine: Optional[ModelScanEngine] = None):
        self.engine = engine or ModelScanEngine()

    def audit_mlflow_directory(self, model_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(model_dir):
            return findings

        mlmodel_file = os.path.join(model_dir, "MLmodel")
        if not os.path.exists(mlmodel_file):
            return findings

        try:
            with open(mlmodel_file, "r", encoding="utf-8") as f:
                manifest = yaml.safe_load(f) or {}
            findings.extend(self._audit_mlmodel_manifest(manifest, mlmodel_file))
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="MLFLOW-MANIFEST-PARSE-ERROR",
                    title="Failed to Parse MLmodel Manifest",
                    severity=RiskLevel.MEDIUM,
                    category="format_validation",
                    description=str(e),
                    location=mlmodel_file,
                )
            )

        # Scan any serialized weights inside the directory
        for root, _, files in os.walk(model_dir):
            for fname in files:
                if fname != "MLmodel" and fname.endswith((".pkl", ".bin", ".pt", ".onnx", ".safetensors")):
                    fpath = os.path.join(root, fname)
                    eval_res, _ = self.engine.scan_path(fpath)
                    findings.extend(eval_res.findings)

        return findings

    def _audit_mlmodel_manifest(self, manifest: Dict[str, Any], location: str) -> List[Finding]:
        findings: List[Finding] = []
        flavors = manifest.get("flavors", {})

        pyfunc = flavors.get("python_function", {})
        if pyfunc:
            # Check for custom code directories
            code_dir = pyfunc.get("code")
            if code_dir:
                findings.append(
                    Finding(
                        rule_id="MLFLOW-CUSTOM-CODE-DIR-FLAGGED",
                        title=f"MLflow Declares Custom Code Path: '{code_dir}'",
                        severity=RiskLevel.HIGH,
                        category="remote_code_execution",
                        description=(
                            "MLflow model bundles a custom code directory that executes upon "
                            "invoking mlflow.pyfunc.load_model()."
                        ),
                        location=location,
                        details={"code_dir": code_dir},
                    )
                )

            # Check loader module
            loader_module = pyfunc.get("loader_module", "")
            if loader_module and not loader_module.startswith("mlflow."):
                findings.append(
                    Finding(
                        rule_id="MLFLOW-THIRD-PARTY-LOADER-MODULE",
                        title=f"Non-Standard MLflow Loader Module: '{loader_module}'",
                        severity=RiskLevel.HIGH,
                        category="dynamic_dispatch",
                        description=f"Model specifies external third-party loader module '{loader_module}'.",
                        location=location,
                        details={"loader_module": loader_module},
                    )
                )

        return findings
