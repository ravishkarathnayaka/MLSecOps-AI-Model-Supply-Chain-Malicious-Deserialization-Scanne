"""
CycloneDX v1.5 AI Software Bill of Materials (AIBOM) Generator.
Produces standardized machine-learning model BOMs according to CycloneDX v1.5 specification.
Enforces EU AI Act and NIST AI RMF supply chain transparency requirements.
"""

from datetime import datetime, timezone
import json
import os
import uuid
from typing import Any, Dict, List, Optional

from scanner.provenance.hash_verifier import HashVerifier
from scanner.rules.policy_engine import EvaluationResult


class CycloneDXAIBOMGenerator:
    """Generates CycloneDX v1.5 JSON AIBOM manifests for scanned ML models."""

    @classmethod
    def generate_bom(
        cls,
        model_path: str,
        evaluation: Optional[EvaluationResult] = None,
        model_name: Optional[str] = None,
        author: str = "MLSecOps Pipeline",
    ) -> Dict[str, Any]:
        basename = os.path.basename(model_path)
        resolved_name = model_name or os.path.splitext(basename)[0]
        ext = os.path.splitext(basename)[1].lower().lstrip(".")

        hashes_list = []
        file_size = 0
        if os.path.exists(model_path):
            digests = HashVerifier.compute_digests(model_path)
            file_size = digests.file_size_bytes
            hashes_list = [
                {"alg": "SHA-256", "content": digests.sha256},
                {"alg": "SHA-512", "content": digests.sha512},
                {"alg": "BLAKE2b-512", "content": digests.blake2b},
            ]

        # Map security findings to CycloneDX vulnerabilities
        vulnerabilities = []
        if evaluation:
            for f in evaluation.findings:
                vulnerabilities.append({
                    "id": f.rule_id,
                    "source": {"name": "MLSecOps-Scanner"},
                    "ratings": [{
                        "severity": f.severity.value.lower(),
                        "score": 9.8 if f.severity.value == "CRITICAL" else 7.5,
                        "method": "CVSSv31",
                    }],
                    "description": f.description,
                    "affects": [{"ref": f"urn:uuid:{basename}"}],
                })

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "MLSecOps",
                        "name": "AI Model Supply Chain Scanner",
                        "version": "1.0.0",
                    }
                ],
                "authors": [{"name": author}],
                "component": {
                    "type": "machine-learning-model",
                    "bom-ref": f"urn:uuid:{basename}",
                    "name": resolved_name,
                    "version": "1.0.0",
                    "description": f"AI/ML Model artifact serialized as {ext.upper()}",
                    "hashes": hashes_list,
                    "properties": [
                        {"name": "mlsecops:format", "value": ext},
                        {"name": "mlsecops:file_size_bytes", "value": str(file_size)},
                    ],
                },
            },
            "components": [
                {
                    "type": "file",
                    "name": basename,
                    "hashes": hashes_list,
                }
            ],
            "vulnerabilities": vulnerabilities,
        }

        return bom
