"""
Hugging Face Model Card Security and Metadata Auditor.
Parses model card YAML frontmatter (README.md) to inspect license integrity,
declared cryptographic digests, and flags dangerous flags like 'trust_remote_code: true'.
"""

import os
import re
from typing import Any, Dict, List, Optional

import yaml

from scanner.provenance.hash_verifier import HashVerifier
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding


class ModelCardAuditor:
    """
    Statically audits Hugging Face Model Card metadata for supply-chain risks.
    """

    @classmethod
    def audit_model_card_file(cls, model_card_path: str, model_weights_path: Optional[str] = None) -> List[Finding]:
        if not os.path.exists(model_card_path):
            return [
                Finding(
                    rule_id="MODELCARD-NOT-FOUND",
                    title="Model Card (README.md) Missing",
                    severity=RiskLevel.LOW,
                    category="documentation",
                    description=f"Model card not found at {model_card_path}.",
                    location=model_card_path,
                )
            ]

        try:
            with open(model_card_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return cls.audit_content(content, source_name=model_card_path, weights_path=model_weights_path)
        except Exception as e:
            return [
                Finding(
                    rule_id="MODELCARD-READ-ERROR",
                    title="Failed to Read Model Card",
                    severity=RiskLevel.LOW,
                    category="io_error",
                    description=str(e),
                    location=model_card_path,
                )
            ]

    @classmethod
    def audit_content(
        cls, content: str, source_name: str = "README.md", weights_path: Optional[str] = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Extract YAML frontmatter enclosed in ---
        yaml_match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
        if not yaml_match:
            findings.append(
                Finding(
                    rule_id="MODELCARD-MISSING-YAML-METADATA",
                    title="Model Card Lacks Structured YAML Frontmatter",
                    severity=RiskLevel.INFO,
                    category="metadata",
                    description="README.md lacks standard Hugging Face YAML metadata header.",
                    location=source_name,
                )
            )
            return findings

        yaml_text = yaml_match.group(1)
        try:
            # Safe load strictly
            metadata = yaml.safe_load(yaml_text) or {}
        except Exception as ex:
            findings.append(
                Finding(
                    rule_id="MODELCARD-CORRUPTED-YAML",
                    title="Malformed YAML Frontmatter in Model Card",
                    severity=RiskLevel.MEDIUM,
                    category="format_validation",
                    description=f"Failed to parse model card YAML: {str(ex)}",
                    location=source_name,
                )
            )
            return findings

        # 1. Audit 'trust_remote_code' or custom code directives
        if metadata.get("custom_code") is True or metadata.get("trust_remote_code") is True:
            findings.append(
                Finding(
                    rule_id="MODELCARD-TRUST-REMOTE-CODE-ENABLED",
                    title="Model Card Enforces 'trust_remote_code: true'",
                    severity=RiskLevel.HIGH,
                    category="remote_code_execution",
                    description=(
                        "Model card declares custom_code or trust_remote_code: true. "
                        "Loading this model prompts execution of unvetted Python scripts hosted on Hub."
                    ),
                    location=source_name,
                    details={"metadata": metadata},
                )
            )

        # 2. Check license declaration
        license_decl = metadata.get("license")
        if not license_decl:
            findings.append(
                Finding(
                    rule_id="MODELCARD-UNDECLARED-LICENSE",
                    title="Model License Undeclared",
                    severity=RiskLevel.INFO,
                    category="compliance",
                    description="No license declared in model card metadata.",
                    location=source_name,
                )
            )

        # 3. Verify declared hashes against weights if weights_path provided
        if weights_path and os.path.exists(weights_path):
            declared_sha256 = metadata.get("sha256")
            if declared_sha256:
                hash_findings = HashVerifier.verify_against_expected(weights_path, expected_sha256=str(declared_sha256))
                findings.extend(hash_findings)

        return findings
