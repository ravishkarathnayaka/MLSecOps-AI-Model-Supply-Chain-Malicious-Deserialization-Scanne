"""
SPDX v2.3 AI Model Bill of Materials (SBOM) Generator.
Produces standardized ISO/IEC 5962:2021 compliant SPDX v2.3 JSON manifests for AI models.
"""

from datetime import datetime, timezone
import os
import uuid
from typing import Any, Dict, List, Optional

from scanner.provenance.hash_verifier import HashVerifier
from scanner.rules.policy_engine import EvaluationResult


class SPDXAIBOMGenerator:
    """Generates SPDX v2.3 JSON document for machine learning model assets."""

    @classmethod
    def generate_spdx(
        cls,
        model_path: str,
        evaluation: Optional[EvaluationResult] = None,
        license_id: str = "MIT",
        creator: str = "Organization: MLSecOps Pipeline",
    ) -> Dict[str, Any]:
        basename = os.path.basename(model_path)
        pkg_id = f"SPDXRef-Package-{uuid.uuid4().hex[:8]}"
        doc_id = f"SPDXRef-DOCUMENT"

        checksums = []
        if os.path.exists(model_path):
            digests = HashVerifier.compute_digests(model_path)
            checksums = [
                {"algorithm": "SHA256", "checksumValue": digests.sha256},
                {"algorithm": "SHA512", "checksumValue": digests.sha512},
            ]

        annotations = []
        if evaluation:
            for idx, f in enumerate(evaluation.findings, 1):
                annotations.append({
                    "annotationDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "annotationType": "REVIEW",
                    "annotator": "Tool: MLSecOps-Scanner-1.0.0",
                    "comment": f"Finding [{f.severity.value}] {f.rule_id}: {f.title}",
                })

        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": doc_id,
            "name": f"AIBOM-{basename}",
            "documentNamespace": f"https://spdx.org/spdxdocs/{basename}-{uuid.uuid4()}",
            "creationInfo": {
                "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "creators": [creator, "Tool: MLSecOps-Scanner-1.0.0"],
            },
            "packages": [
                {
                    "name": basename,
                    "SPDXID": pkg_id,
                    "packageFileName": basename,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": license_id,
                    "licenseDeclared": license_id,
                    "copyrightText": "NOASSERTION",
                    "checksums": checksums,
                }
            ],
            "annotations": annotations,
        }

        return spdx_doc
