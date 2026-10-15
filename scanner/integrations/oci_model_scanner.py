"""
OCI (Open Container Initiative) and ORAS Model Artifact Scanner.
Inspects container registry model manifests (application/vnd.oci.image.manifest.v1+json)
and layer media types to enforce supply chain policies before container pull.
"""

from typing import Any, Dict, List, Optional
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class OCIModelScanner:
    """Audits OCI model image manifests and layer annotations."""

    FORBIDDEN_LAYER_MEDIA_TYPES = {
        "application/vnd.pytorch.pickle.layer.v1": "Direct pickle-serialized tensor layer",
        "application/vnd.python.bytecode": "Embedded raw Python bytecode inside OCI layer",
    }

    def __init__(self, require_safetensors: bool = False):
        self.require_safetensors = require_safetensors

    def scan_manifest(self, manifest: Dict[str, Any], image_ref: str = "registry/model:latest") -> List[Finding]:
        findings: List[Finding] = []

        schema_version = manifest.get("schemaVersion")
        if schema_version != 2:
            findings.append(
                Finding(
                    rule_id="OCI-NONSTANDARD-SCHEMA-VERSION",
                    title="Non-Standard OCI Manifest Schema Version",
                    severity=RiskLevel.MEDIUM,
                    description=f"Manifest uses schemaVersion {schema_version}, expected 2.",
                    location=image_ref,
                    category="format_anomaly",
                )
            )

        layers = manifest.get("layers", [])
        if not isinstance(layers, list) or len(layers) == 0:
            findings.append(
                Finding(
                    rule_id="OCI-EMPTY-MANIFEST-LAYERS",
                    title="OCI Model Manifest Contains Zero Layers",
                    severity=RiskLevel.HIGH,
                    description="Manifest does not define any content layers.",
                    location=image_ref,
                    category="format_anomaly",
                )
            )
            return findings

        for idx, layer in enumerate(layers):
            if not isinstance(layer, dict):
                continue
            media_type = layer.get("mediaType", "")
            digest = layer.get("digest", "")

            # Check for dangerous layer types
            if media_type in self.FORBIDDEN_LAYER_MEDIA_TYPES:
                findings.append(
                    Finding(
                        rule_id="OCI-PROHIBITED-LAYER-MEDIA-TYPE",
                        title=f"Prohibited OCI Layer Media Type: {media_type}",
                        severity=RiskLevel.CRITICAL,
                        description=f"{self.FORBIDDEN_LAYER_MEDIA_TYPES[media_type]} in layer [{idx}].",
                        location=f"{image_ref}:layer[{idx}]",
                        category="supply_chain_integrity",
                    )
                )

            # Check digest format
            if not digest or not digest.startswith("sha256:"):
                findings.append(
                    Finding(
                        rule_id="OCI-INVALID-LAYER-DIGEST",
                        title="Invalid Layer Cryptographic Digest in OCI Manifest",
                        severity=RiskLevel.HIGH,
                        description=f"Layer [{idx}] missing standard sha256 prefix: {digest}",
                        location=f"{image_ref}:layer[{idx}]",
                        category="provenance_integrity",
                    )
                )

        return findings
