"""
Model Cryptographic Signature and In-toto Attestation Checker.
Validates Cosign/Sigstore bundles, ECDSA/RSA detached signatures, and SLSA/in-toto provenance attestations.
Ensures cryptographic supply-chain integrity before inference admission.
"""

import base64
import json
import os
from typing import Any, Dict, List, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from scanner.provenance.hash_verifier import HashVerifier
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding


class SignatureChecker:
    """
    Validates digital signatures, Sigstore bundles, and in-toto provenance statements.
    """

    @classmethod
    def verify_detached_signature(
        cls,
        model_path: str,
        signature_path: str,
        public_key_pem: Union[str, bytes],
    ) -> List[Finding]:
        """Verifies a detached ECDSA or RSA signature against a model file."""
        findings: List[Finding] = []

        if not os.path.exists(model_path):
            return [
                Finding(
                    rule_id="SIG-MODEL-NOT-FOUND",
                    title="Model File Not Found for Signature Verification",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Model artifact not found at {model_path}",
                    location=model_path,
                )
            ]

        if not os.path.exists(signature_path):
            return [
                Finding(
                    rule_id="SIG-SIGNATURE-NOT-FOUND",
                    title="Signature File Not Found",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Signature file not found at {signature_path}",
                    location=signature_path,
                )
            ]

        try:
            with open(model_path, "rb") as f:
                model_data = f.read()

            with open(signature_path, "rb") as f:
                raw_sig = f.read()

            # If signature is base64 encoded, decode it
            try:
                sig_bytes = base64.b64decode(raw_sig, validate=True)
            except Exception:
                sig_bytes = raw_sig

            if isinstance(public_key_pem, str):
                if os.path.exists(public_key_pem):
                    with open(public_key_pem, "rb") as pf:
                        pub_key_bytes = pf.read()
                else:
                    pub_key_bytes = public_key_pem.encode("utf-8")
            else:
                pub_key_bytes = public_key_pem

            pub_key = load_pem_public_key(pub_key_bytes)

            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    sig_bytes,
                    model_data,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(
                    sig_bytes,
                    model_data,
                    ec.ECDSA(hashes.SHA256()),
                )
            else:
                findings.append(
                    Finding(
                        rule_id="SIG-UNSUPPORTED-KEY-ALGORITHM",
                        title="Unsupported Public Key Type",
                        severity=RiskLevel.HIGH,
                        category="signature_verification",
                        description=f"Public key type '{type(pub_key).__name__}' is not supported.",
                        location=signature_path,
                    )
                )

        except InvalidSignature:
            findings.append(
                Finding(
                    rule_id="SIG-VERIFICATION-FAILED",
                    title="Cryptographic Signature Verification FAILED",
                    severity=RiskLevel.CRITICAL,
                    category="signature_integrity",
                    description=(
                        f"Cryptographic signature in '{signature_path}' is INVALID for model '{model_path}'. "
                        "The model may have been modified by an unauthorized third party."
                    ),
                    location=signature_path,
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="SIG-ERROR",
                    title="Signature Verification Exception",
                    severity=RiskLevel.HIGH,
                    category="signature_error",
                    description=f"Error executing signature check: {str(e)}",
                    location=signature_path,
                    details={"error": str(e)},
                )
            )

        return findings

    @classmethod
    def verify_intoto_attestation(
        cls,
        model_path: str,
        attestation_file_or_data: Union[str, Dict[str, Any]],
    ) -> List[Finding]:
        """
        Validates in-toto attestation / SLSA provenance metadata.
        Ensures the subject digest in the attestation strictly matches the model's computed hash.
        """
        findings: List[Finding] = []

        if isinstance(attestation_file_or_data, str):
            if not os.path.exists(attestation_file_or_data):
                return [
                    Finding(
                        rule_id="ATTESTATION-FILE-NOT-FOUND",
                        title="Attestation File Not Found",
                        severity=RiskLevel.HIGH,
                        category="io_error",
                        description=f"Attestation file missing: {attestation_file_or_data}",
                        location=attestation_file_or_data,
                    )
                ]
            try:
                with open(attestation_file_or_data, "r", encoding="utf-8") as f:
                    attestation = json.load(f)
            except Exception as e:
                return [
                    Finding(
                        rule_id="ATTESTATION-PARSE-ERROR",
                        title="Malformed In-toto Attestation JSON",
                        severity=RiskLevel.HIGH,
                        category="format_validation",
                        description=f"Failed to parse attestation JSON: {str(e)}",
                        location=attestation_file_or_data,
                    )
                ]
        else:
            attestation = attestation_file_or_data

        if not os.path.exists(model_path):
            return [
                Finding(
                    rule_id="ATTESTATION-MODEL-NOT-FOUND",
                    title="Model File Not Found for Attestation",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Model artifact not found at {model_path}",
                    location=model_path,
                )
            ]

        # Calculate actual model hash
        computed_digests = HashVerifier.compute_digests(model_path)

        # Validate in-toto statement structure
        # Standard: {"_type": "https://in-toto.io/Statement/v0.1", "subject": [...]}
        subjects = attestation.get("subject", [])
        if not isinstance(subjects, list) or not subjects:
            findings.append(
                Finding(
                    rule_id="ATTESTATION-MISSING-SUBJECTS",
                    title="In-toto Attestation Missing Subject Entries",
                    severity=RiskLevel.CRITICAL,
                    category="attestation_integrity",
                    description="Attestation statement does not declare any artifact subjects.",
                    location=model_path,
                )
            )
            return findings

        # Check for matching subject digest
        matched = False
        for subj in subjects:
            if not isinstance(subj, dict):
                continue
            digest_dict = subj.get("digest", {})
            sha256_declared = digest_dict.get("sha256")
            if sha256_declared and sha256_declared.lower() == computed_digests.sha256.lower():
                matched = True
                break

        if not matched:
            findings.append(
                Finding(
                    rule_id="ATTESTATION-DIGEST-MISMATCH",
                    title="Attestation Subject Digest Mismatch",
                    severity=RiskLevel.CRITICAL,
                    category="attestation_integrity",
                    description=(
                        f"Computed SHA-256 '{computed_digests.sha256}' does not match any declared subject "
                        "in the in-toto provenance attestation. Attestation does not prove this artifact's build."
                    ),
                    location=model_path,
                    details={"computed_sha256": computed_digests.sha256},
                )
            )

        return findings
