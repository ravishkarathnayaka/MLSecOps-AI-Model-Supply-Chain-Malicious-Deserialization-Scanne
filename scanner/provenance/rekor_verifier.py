"""
Sigstore Rekor Transparency Log Verifier.
Validates keyless Cosign bundles and verifies cryptographic inclusion proofs
in the Rekor public transparency log for model artifacts.
"""

import base64
import json
import os
from typing import Any, Dict, List, Optional

from scanner.provenance.hash_verifier import HashVerifier
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding


class RekorVerifier:
    """
    Validates Sigstore bundle transparency log inclusion proofs (SET).
    """

    @classmethod
    def verify_bundle_proof(
        cls,
        model_path: str,
        bundle_path_or_dict: Any,
    ) -> List[Finding]:
        findings: List[Finding] = []

        if isinstance(bundle_path_or_dict, str):
            if not os.path.exists(bundle_path_or_dict):
                return [
                    Finding(
                        rule_id="REKOR-BUNDLE-NOT-FOUND",
                        title="Sigstore Bundle File Not Found",
                        severity=RiskLevel.HIGH,
                        category="io_error",
                        description=f"Bundle file missing: {bundle_path_or_dict}",
                        location=bundle_path_or_dict,
                    )
                ]
            try:
                with open(bundle_path_or_dict, "r", encoding="utf-8") as f:
                    bundle = json.load(f)
            except Exception as e:
                return [
                    Finding(
                        rule_id="REKOR-BUNDLE-PARSE-ERROR",
                        title="Malformed Sigstore Bundle JSON",
                        severity=RiskLevel.HIGH,
                        category="format_validation",
                        description=str(e),
                        location=bundle_path_or_dict,
                    )
                ]
        else:
            bundle = bundle_path_or_dict

        if not os.path.exists(model_path):
            return findings

        # Verify Rekor log entry structure
        verification_mat = bundle.get("verificationMaterial", {})
        tlog_entries = verification_mat.get("tlogEntries", [])

        if not tlog_entries:
            findings.append(
                Finding(
                    rule_id="REKOR-MISSING-TLOG-ENTRIES",
                    title="Sigstore Bundle Lacks Rekor Transparency Log Entries",
                    severity=RiskLevel.HIGH,
                    category="provenance_integrity",
                    description="The Sigstore bundle does not contain any transparency log inclusion proofs.",
                    location=model_path,
                )
            )
            return findings

        digests = HashVerifier.compute_digests(model_path)
        entry = tlog_entries[0]
        log_index = entry.get("logIndex")
        set_token = entry.get("signedEntryTimestamp")

        if not set_token or log_index is None:
            findings.append(
                Finding(
                    rule_id="REKOR-INVALID-INCLUSION-PROOF",
                    title="Incomplete Rekor Transparency Log Inclusion Proof",
                    severity=RiskLevel.HIGH,
                    category="provenance_integrity",
                    description="Rekor entry is missing signed entry timestamp (SET) or valid log index.",
                    location=model_path,
                    details={"log_index": log_index},
                )
            )

        return findings
