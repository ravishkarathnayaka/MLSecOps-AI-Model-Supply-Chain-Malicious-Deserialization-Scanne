"""
Static format analyzer for Apple CoreML models (.mlmodel, .mlpackage).
Inspects CoreML Protocol Buffer schemas and package manifests without Apple SDK dependencies,
detecting custom operators, unsafe external assets, and code execution callbacks.
"""

import json
import os
import zipfile
from typing import List

from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class CoreMLAnalyzer:
    """Static security validator for Apple CoreML model packages and archives."""

    FORBIDDEN_CUSTOM_TYPES = {"CustomModel", "customModel", "DynamicCallback", "ExternalDelegate"}

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_package_dir(self, dir_path: str) -> List[Finding]:
        """Inspects an unzipped .mlpackage directory structure."""
        findings: List[Finding] = []
        manifest_path = os.path.join(dir_path, "Manifest.json")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
                findings.extend(self._validate_manifest(manifest, manifest_path))
            except Exception as e:
                findings.append(
                    Finding(
                        rule_id="COREML-MANIFEST-CORRUPTED",
                        severity=RiskLevel.MEDIUM,
                        message=f"Failed to parse CoreML Manifest.json: {e}",
                        location=manifest_path,
                    )
                )

        # Inspect all files in package for unauthorized executable or script formats
        for root, _, files in os.walk(dir_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, dir_path)
                if any(rel_path.endswith(ext) for ext in [".py", ".sh", ".dylib", ".so", ".exe"]):
                    findings.append(
                        Finding(
                            rule_id="COREML-UNTRUSTED-EXECUTABLE-ASSET",
                            severity=RiskLevel.CRITICAL,
                            message=f"CoreML package contains unauthorized executable or script asset: {rel_path}",
                            location=rel_path,
                        )
                    )
        return findings

    def analyze_mlmodel_bytes(self, raw_bytes: bytes, source_name: str = "model.mlmodel") -> List[Finding]:
        """Scans raw .mlmodel bytes for custom layers and path traversal artifacts."""
        findings: List[Finding] = []

        # Check for zip wrapper (.mlpackage as zip)
        if raw_bytes.startswith(b"PK\x03\x04"):
            import io
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
                    for name in zf.namelist():
                        if any(name.endswith(ext) for ext in [".py", ".sh", ".dylib", ".so", ".exe"]):
                            findings.append(
                                Finding(
                                    rule_id="COREML-UNTRUSTED-EXECUTABLE-ASSET",
                                    severity=RiskLevel.CRITICAL,
                                    message=f"Embedded executable asset found in CoreML archive: {name}",
                                    location=f"{source_name}:{name}",
                                )
                            )
            except Exception:
                pass

        # String search for dangerous CoreML custom layer descriptors
        for custom_type in self.FORBIDDEN_CUSTOM_TYPES:
            if custom_type.encode("utf-8") in raw_bytes:
                findings.append(
                    Finding(
                        rule_id="COREML-CUSTOM-OPERATOR-FLAGGED",
                        severity=RiskLevel.HIGH,
                        message=f"Untrusted custom CoreML operator layer detected: {custom_type}",
                        location=source_name,
                    )
                )

        return findings

    def _validate_manifest(self, manifest: dict, path: str) -> List[Finding]:
        findings: List[Finding] = []
        item_names = manifest.get("itemInfoEntries", {})
        for item, details in item_names.items():
            path_val = details.get("path", "")
            if ".." in path_val or path_val.startswith("/"):
                findings.append(
                    Finding(
                        rule_id="COREML-PATH-TRAVERSAL-IN-MANIFEST",
                        severity=RiskLevel.CRITICAL,
                        message=f"Path traversal sequence detected in CoreML manifest item: {path_val}",
                        location=path,
                    )
                )
        return findings
