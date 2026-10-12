"""
vLLM Model Loading Pre-Flight Admission Guard.
Intercepts high-throughput LLM engine weight loading to ensure model files satisfy
zero-executable memory guarantees before allocation in GPU High-Bandwidth Memory (HBM).
"""

from dataclasses import dataclass, field
import os
from typing import Any, Dict, List, Optional

from scanner.core.engine import ModelScanEngine
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import EvaluationResult


@dataclass
class GuardVerdict:
    admitted: bool
    model_identifier: str
    rejection_reason: Optional[str] = None
    violation_count: int = 0
    details: Dict[str, Any] = field(default_factory=dict)


class vLLMAdmissionGuard:
    """
    Enforces supply chain security gates prior to vLLM engine weight loading.
    Prefers Safetensors over unsafe PyTorch pickle binaries.
    """

    def __init__(
        self,
        require_safetensors_only: bool = False,
        fail_on_threshold: RiskLevel = RiskLevel.HIGH,
        scan_engine: Optional[ModelScanEngine] = None,
    ):
        self.require_safetensors_only = require_safetensors_only
        self.fail_on_threshold = fail_on_threshold
        self.engine = scan_engine or ModelScanEngine(fail_on_threshold=fail_on_threshold)

    def evaluate_model_path(self, model_path: str) -> GuardVerdict:
        """Inspects directory or file before passing to vLLM engine."""
        if not os.path.exists(model_path):
            return GuardVerdict(
                admitted=False,
                model_identifier=model_path,
                rejection_reason=f"Model path does not exist: {model_path}",
            )

        # If strict safetensors is enforced, check for legacy pickle files
        if self.require_safetensors_only:
            for root, _, files in os.walk(model_path) if os.path.isdir(model_path) else [("", [os.path.basename(model_path)])]:
                for f in files:
                    if f.lower().endswith((".bin", ".pt", ".pth", ".pkl")):
                        return GuardVerdict(
                            admitted=False,
                            model_identifier=model_path,
                            rejection_reason=f"Strict policy: Legacy serialized file '{f}' prohibited when Safetensors required.",
                        )

        # Perform static scan
        eval_result, scanned_files = self.engine.scan_path(model_path)
        if not eval_result.passed:
            first_viol = eval_result.violations[0].description if eval_result.violations else "Policy check failed"
            return GuardVerdict(
                admitted=False,
                model_identifier=model_path,
                rejection_reason=f"Security scan rejected model: {first_viol}",
                violation_count=len(eval_result.violations),
                details={"violations": [v.to_dict() for v in eval_result.violations]},
            )

        return GuardVerdict(
            admitted=True,
            model_identifier=model_path,
            details={"scanned_files": len(scanned_files)},
        )
