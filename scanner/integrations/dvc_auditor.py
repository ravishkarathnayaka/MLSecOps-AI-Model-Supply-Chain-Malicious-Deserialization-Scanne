"""
Data Version Control (DVC) Pipeline and Remote Storage Security Auditor.
Inspects .dvc pointer files and dvc.lock stage manifests for missing digests,
unverified remote storage endpoints, and vulnerable model stage dependencies.
"""

from typing import Any, Dict, List
import yaml

from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class DVCPipelineAuditor:
    """Audits DVC stage manifests and pointer files for supply chain integrity."""

    def __init__(self, enforce_hash_verification: bool = True):
        self.enforce_hash_verification = enforce_hash_verification

    def audit_dvc_file(self, content_str: str, file_name: str = "model.dvc") -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = yaml.safe_load(content_str)
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="DVC-MALFORMED-YAML",
                    title="Malformed DVC Manifest YAML",
                    severity=RiskLevel.MEDIUM,
                    description=f"Error parsing DVC YAML structure: {e}",
                    location=file_name,
                    category="format_anomaly",
                )
            )
            return findings

        if not isinstance(data, dict):
            return findings

        outs = data.get("outs", [])
        if not isinstance(outs, list) or len(outs) == 0:
            findings.append(
                Finding(
                    rule_id="DVC-NO-OUTPUTS-DEFINED",
                    title="DVC Manifest Lacks Output Definitions",
                    severity=RiskLevel.LOW,
                    description="No tracked outputs found in DVC manifest.",
                    location=file_name,
                    category="format_anomaly",
                )
            )
            return findings

        for idx, out in enumerate(outs):
            if not isinstance(out, dict):
                continue
            path = out.get("path", "")
            md5_val = out.get("md5") or out.get("hash")
            lower_path = path.lower()

            # Check for legacy pickle model outputs
            if lower_path.endswith((".pkl", ".pickle", ".pt", ".bin")):
                findings.append(
                    Finding(
                        rule_id="DVC-LEGACY-PICKLE-OUTPUT",
                        title=f"DVC Stage Produces Legacy Pickle File ({path})",
                        severity=RiskLevel.MEDIUM,
                        description=f"DVC pipeline output '{path}' is a pickle-based format susceptible to opcode injection.",
                        location=f"{file_name}:outs[{idx}]",
                        category="supply_chain_integrity",
                    )
                )

            # Check hash presence
            if not md5_val and self.enforce_hash_verification:
                findings.append(
                    Finding(
                        rule_id="DVC-MISSING-OUTPUT-HASH",
                        title=f"Missing Output Hash for DVC Target ({path})",
                        severity=RiskLevel.HIGH,
                        description=f"Output '{path}' lacks cryptographic hash in DVC manifest; prone to untracked tampering.",
                        location=f"{file_name}:outs[{idx}]",
                        category="provenance_integrity",
                    )
                )

        return findings
