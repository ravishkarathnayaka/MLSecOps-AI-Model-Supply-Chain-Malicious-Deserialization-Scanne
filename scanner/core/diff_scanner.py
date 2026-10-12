"""
Differential Model Security Scanner (ModelDiff).
Compares baseline vs candidate model versions to detect newly introduced security findings,
payload injections, and supply-chain regressions during model fine-tuning or retraining.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from scanner.core.engine import ModelScanEngine
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import EvaluationResult, Finding


@dataclass
class ModelDiffReport:
    baseline_path: str
    candidate_path: str
    new_findings: List[Finding]
    resolved_findings: List[Finding]
    regression_detected: bool
    summary: str


class ModelDiffScanner:
    """
    Compares two model artifact versions to detect newly introduced vulnerabilities.
    """

    def __init__(self, engine: Optional[ModelScanEngine] = None):
        self.engine = engine or ModelScanEngine()

    def compare_models(self, baseline_path: str, candidate_path: str) -> ModelDiffReport:
        eval_base, _ = self.engine.scan_path(baseline_path)
        eval_cand, _ = self.engine.scan_path(candidate_path)

        base_rules: Set[str] = {f.rule_id for f in eval_base.findings}
        cand_rules: Set[str] = {f.rule_id for f in eval_cand.findings}

        new_findings = [f for f in eval_cand.findings if f.rule_id not in base_rules]
        resolved_findings = [f for f in eval_base.findings if f.rule_id not in cand_rules]

        regression_detected = any(
            f.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH) for f in new_findings
        )

        if regression_detected:
            summary = f"SECURITY REGRESSION: Candidate introduced {len(new_findings)} new security finding(s)."
        elif new_findings:
            summary = f"WARNING: Candidate introduced {len(new_findings)} non-blocking finding(s)."
        else:
            summary = "NO REGRESSION: Candidate model introduced zero new vulnerabilities."

        return ModelDiffReport(
            baseline_path=baseline_path,
            candidate_path=candidate_path,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            regression_detected=regression_detected,
            summary=summary,
        )
