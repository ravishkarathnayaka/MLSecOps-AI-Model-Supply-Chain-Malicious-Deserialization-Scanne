"""
Weights & Biases (W&B) Artifact Registry Security Auditor.
Validates model artifact manifests, digests, and metadata logged to W&B
preventing unverified or malicious deserialization packages from deployment gates.
"""

from typing import Any, Dict, List, Optional
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class WandbArtifactAuditor:
    """Audits Weights & Biases logged model artifacts and manifests."""

    def __init__(self, require_signatures: bool = False):
        self.require_signatures = require_signatures

    def audit_manifest(self, manifest: Dict[str, Any], artifact_id: str = "wandb-artifact") -> List[Finding]:
        findings: List[Finding] = []
        entries = manifest.get("contents", {})
        if not isinstance(entries, dict):
            return findings

        has_legacy_pickle = False
        has_safetensors = False

        for file_name, file_meta in entries.items():
            lower_name = file_name.lower()
            if lower_name.endswith((".pkl", ".pickle", ".pt", ".pth", ".bin")):
                has_legacy_pickle = True
                findings.append(
                    Finding(
                        rule_id="WANDB-LEGACY-DESERIALIZATION-ARTIFACT",
                        title=f"W&B Artifact Contains Legacy Pickle Format ({file_name})",
                        severity=RiskLevel.MEDIUM,
                        description=f"Artifact entry '{file_name}' utilizes vulnerable Python serialization.",
                        location=f"{artifact_id}:{file_name}",
                        category="supply_chain_integrity",
                    )
                )
            elif lower_name.endswith(".safetensors"):
                has_safetensors = True

            # Check digest integrity
            digest = file_meta.get("digest") if isinstance(file_meta, dict) else None
            if not digest:
                findings.append(
                    Finding(
                        rule_id="WANDB-MISSING-DIGEST-CHECKSUM",
                        title="Missing Cryptographic Digest for W&B File Entry",
                        severity=RiskLevel.HIGH,
                        description=f"Manifest entry '{file_name}' lacks a verifiable cryptographic digest.",
                        location=f"{artifact_id}:{file_name}",
                        category="provenance_integrity",
                    )
                )

        # Audit metadata tags
        metadata = manifest.get("metadata", {})
        if isinstance(metadata, dict):
            if metadata.get("untrusted_source") is True:
                findings.append(
                    Finding(
                        rule_id="WANDB-UNTRUSTED-SOURCE-FLAG",
                        title="Artifact Explicitly Tagged as Untrusted Source",
                        severity=RiskLevel.HIGH,
                        description=f"W&B metadata indicates external or unverified origin for {artifact_id}.",
                        location=artifact_id,
                        category="provenance_integrity",
                    )
                )

        return findings
