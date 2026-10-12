"""
Generates SLSA (Supply-chain Levels for Software Artifacts) v1.0 provenance predicates
and in-toto statement envelopes for machine learning model artifacts.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


class SLSAGenerator:
    """Generates SLSA v1.0 in-toto provenance statements for model artifacts."""

    BUILD_TYPE_URI = "https://mlsecops.dev/attestation/model-build/v1"
    PREDICATE_TYPE_V1 = "https://slsa.dev/provenance/v1"
    INTOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"

    def __init__(self, builder_id: str = "https://github.com/ravishkarathnayaka/MLSecOps"):
        self.builder_id = builder_id

    def generate_statement(
        self,
        model_name: str,
        sha256_hash: str,
        source_repository: str,
        commit_sha: Optional[str] = None,
        dependencies: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Builds a complete in-toto statement envelope carrying SLSA v1.0 provenance."""
        now_iso = datetime.now(timezone.utc).isoformat()
        invocation_id = str(uuid.uuid4())

        subject = [
            {
                "name": model_name,
                "digest": {"sha256": sha256_hash},
            }
        ]

        resolved_deps = []
        if dependencies:
            for dep in dependencies:
                resolved_deps.append({
                    "uri": dep.get("uri", ""),
                    "digest": {"sha256": dep.get("sha256", "")},
                })

        predicate = {
            "buildDefinition": {
                "buildType": self.BUILD_TYPE_URI,
                "externalParameters": {
                    "sourceRepository": source_repository,
                    "sourceCommit": commit_sha or "HEAD",
                },
                "internalParameters": {
                    "scannerTool": "MLSecOps-AI-Model-Scanner",
                    "scannerVersion": "1.0.0",
                },
                "resolvedDependencies": resolved_deps,
            },
            "runDetails": {
                "builder": {
                    "id": self.builder_id,
                },
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": now_iso,
                    "finishedOn": now_iso,
                },
                "byproducts": [],
            },
        }

        statement = {
            "_type": self.INTOTO_STATEMENT_V1,
            "subject": subject,
            "predicateType": self.PREDICATE_TYPE_V1,
            "predicate": predicate,
        }
        return statement
