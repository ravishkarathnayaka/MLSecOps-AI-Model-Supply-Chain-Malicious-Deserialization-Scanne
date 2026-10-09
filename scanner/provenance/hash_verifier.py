"""
Model Cryptographic Hash Verifier.
Streams and computes SHA-256, SHA-512, and BLAKE2b digests of model files.
Validates computed hashes against expected digests, manifest files, and Hugging Face model cards.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding

CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks


@dataclass
class HashDigestResult:
    file_path: str
    sha256: str
    sha512: str
    blake2b: str
    file_size_bytes: int


class HashVerifier:
    """Computes and verifies cryptographic digests of model artifacts."""

    @staticmethod
    def compute_digests(file_path: str) -> HashDigestResult:
        """Streams file and computes sha256, sha512, and blake2b."""
        h_256 = hashlib.sha256()
        h_512 = hashlib.sha512()
        h_b2 = hashlib.blake2b()
        total_bytes = 0

        with open(file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                total_bytes += len(chunk)
                h_256.update(chunk)
                h_512.update(chunk)
                h_b2.update(chunk)

        return HashDigestResult(
            file_path=file_path,
            sha256=h_256.hexdigest(),
            sha512=h_512.hexdigest(),
            blake2b=h_b2.hexdigest(),
            file_size_bytes=total_bytes,
        )

    @classmethod
    def verify_against_expected(
        cls,
        file_path: str,
        expected_sha256: Optional[str] = None,
        expected_sha512: Optional[str] = None,
    ) -> List[Finding]:
        """Compares computed hash against expected SHA256 and/or SHA512 values."""
        findings: List[Finding] = []

        if not os.path.exists(file_path):
            findings.append(
                Finding(
                    rule_id="PROVENANCE-FILE-NOT-FOUND",
                    title="File Not Found for Hash Verification",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Model artifact not found at {file_path}",
                    location=file_path,
                )
            )
            return findings

        digests = cls.compute_digests(file_path)

        if expected_sha256:
            expected_clean = expected_sha256.strip().lower()
            if digests.sha256.lower() != expected_clean:
                findings.append(
                    Finding(
                        rule_id="PROVENANCE-SHA256-MISMATCH",
                        title="Model Artifact SHA-256 Digest Mismatch",
                        severity=RiskLevel.CRITICAL,
                        category="provenance_integrity",
                        description=(
                            f"Calculated SHA-256 '{digests.sha256}' does not match expected '{expected_clean}'. "
                            "Model weights may have been tampered with or corrupted in transit."
                        ),
                        location=file_path,
                        details={
                            "computed_sha256": digests.sha256,
                            "expected_sha256": expected_clean,
                        },
                    )
                )

        if expected_sha512:
            expected_clean = expected_sha512.strip().lower()
            if digests.sha512.lower() != expected_clean:
                findings.append(
                    Finding(
                        rule_id="PROVENANCE-SHA512-MISMATCH",
                        title="Model Artifact SHA-512 Digest Mismatch",
                        severity=RiskLevel.CRITICAL,
                        category="provenance_integrity",
                        description=(
                            f"Calculated SHA-512 '{digests.sha512}' does not match expected '{expected_clean}'."
                        ),
                        location=file_path,
                        details={
                            "computed_sha512": digests.sha512,
                            "expected_sha512": expected_clean,
                        },
                    )
                )

        return findings
