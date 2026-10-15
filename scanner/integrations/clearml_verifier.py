"""
ClearML Model Repository Security Verification Client.
Audits ClearML model entities, storage URIs, lineage labels, and frameworks
to enforce supply chain security gates prior to model promotion in production pipelines.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class ClearMLModelVerifier:
    """Verifies security attributes of models registered in ClearML."""

    ALLOWED_SCHEMES = {"s3", "gs", "azure", "https"}

    def __init__(self, enforce_tls: bool = True):
        self.enforce_tls = enforce_tls

    def verify_model_record(self, record: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        model_id = record.get("id", "unknown-id")
        model_name = record.get("name", "unnamed-model")
        uri = record.get("uri", "")

        # Check storage URI
        if uri:
            parsed = urlparse(uri)
            if parsed.scheme == "http" and self.enforce_tls:
                findings.append(
                    Finding(
                        rule_id="CLEARML-INSECURE-HTTP-STORAGE-URI",
                        title="Insecure Plaintext Storage URI in ClearML Model Record",
                        severity=RiskLevel.HIGH,
                        description=f"Model storage URI uses plaintext HTTP: {uri}",
                        location=f"clearml:{model_id}",
                        category="transport_security",
                    )
                )
            elif parsed.scheme not in self.ALLOWED_SCHEMES and not parsed.scheme.startswith("file"):
                findings.append(
                    Finding(
                        rule_id="CLEARML-UNTRUSTED-STORAGE-SCHEME",
                        title=f"Untrusted Storage Scheme '{parsed.scheme}' in ClearML Record",
                        severity=RiskLevel.MEDIUM,
                        description=f"Model URI '{uri}' uses non-standard storage scheme.",
                        location=f"clearml:{model_id}",
                        category="supply_chain_integrity",
                    )
                )

        # Check framework
        framework = str(record.get("framework", "")).lower()
        if "pickle" in framework or framework == "pt_legacy":
            findings.append(
                Finding(
                    rule_id="CLEARML-UNSAFE-FRAMEWORK-TYPE",
                    title="ClearML Model Uses Inherently Unsafe Framework Serialization",
                    severity=RiskLevel.HIGH,
                    description=f"Registered framework type '{framework}' is vulnerable to code execution.",
                    location=f"clearml:{model_id}",
                    category="framework_security",
                )
            )

        # Check tags for quarantined or untrusted status
        tags = record.get("tags", [])
        if isinstance(tags, list):
            for t in tags:
                if str(t).lower() in ("quarantined", "unverified", "suspicious"):
                    findings.append(
                        Finding(
                            rule_id="CLEARML-TAGGED-QUARANTINED",
                            title=f"Model Flagged with Warning Tag: {t}",
                            severity=RiskLevel.CRITICAL if str(t).lower() == "quarantined" else RiskLevel.HIGH,
                            description=f"ClearML model possesses risk tag: {t}",
                            location=f"clearml:{model_id}",
                            category="policy_gate",
                        )
                    )

        return findings
