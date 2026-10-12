"""
Static security analyzer for TensorFlow SavedModel directory structures and Protobuf graphs.
Inspects saved_model.pb, variables/, and assets/ for PyFunc execution hooks, symlink escapes,
and unauthorized script assets without TensorFlow runtime dependencies.
"""

import os
from typing import List

from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class SavedModelAnalyzer:
    """Static security validator for TensorFlow SavedModel directories and protobuf bundles."""

    FORBIDDEN_OPERATORS = {
        b"PyFunc": "Executes arbitrary Python function inside TensorFlow computation graph",
        b"PyFuncStateless": "Executes stateless arbitrary Python function in graph",
        b"EagerPyFunc": "Executes arbitrary eager Python callback in graph",
        b"CustomOp": "Unverified custom C++ kernel registration",
    }

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_savedmodel_dir(self, dir_path: str) -> List[Finding]:
        """Inspects SavedModel folder structure, assets, and protobuf binary."""
        findings: List[Finding] = []

        if not os.path.exists(dir_path):
            findings.append(
                Finding(
                    rule_id="SAVEDMODEL-NOT-FOUND",
                    title="SavedModel Path Does Not Exist",
                    severity=RiskLevel.HIGH,
                    description=f"Specified SavedModel path not found: {dir_path}",
                    location=dir_path,
                )
            )
            return findings

        # Check for saved_model.pb or saved_model.pbtxt
        pb_path = os.path.join(dir_path, "saved_model.pb")
        pbtxt_path = os.path.join(dir_path, "saved_model.pbtxt")
        if os.path.exists(pb_path):
            with open(pb_path, "rb") as f:
                pb_bytes = f.read()
            findings.extend(self._scan_pb_bytes(pb_bytes, pb_path))
        elif os.path.exists(pbtxt_path):
            with open(pbtxt_path, "rb") as f:
                pb_bytes = f.read()
            findings.extend(self._scan_pb_bytes(pb_bytes, pbtxt_path))
        else:
            findings.append(
                Finding(
                    rule_id="SAVEDMODEL-MISSING-GRAPH-DEF",
                    title="Missing SavedModel Protobuf Graph",
                    severity=RiskLevel.HIGH,
                    description="SavedModel directory is missing saved_model.pb or saved_model.pbtxt",
                    location=dir_path,
                )
            )

        # Inspect assets and variables directory
        for root, _, files in os.walk(dir_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, dir_path)

                # Check for symlink traversal
                if os.path.islink(full_path):
                    target = os.readlink(full_path)
                    if ".." in target or os.path.isabs(target):
                        findings.append(
                            Finding(
                                rule_id="SAVEDMODEL-DANGEROUS-SYMLINK",
                                title="Dangerous Symlink in SavedModel Directory",
                                severity=RiskLevel.CRITICAL,
                                description=f"Symlink points outside model directory: {rel_path} -> {target}",
                                location=rel_path,
                            )
                        )

                # Check for executable scripts in assets/ or root
                if any(file.lower().endswith(ext) for ext in [".py", ".sh", ".bat", ".cmd", ".so", ".dll", ".exe"]):
                    findings.append(
                        Finding(
                            rule_id="SAVEDMODEL-UNTRUSTED-ASSET-FILE",
                            title="Untrusted Executable Asset File in SavedModel",
                            severity=RiskLevel.CRITICAL,
                            description=f"Disallowed executable file type found in SavedModel bundle: {rel_path}",
                            location=rel_path,
                        )
                    )

        return findings

    def _scan_pb_bytes(self, raw_bytes: bytes, source_name: str) -> List[Finding]:
        findings: List[Finding] = []
        for op, desc in self.FORBIDDEN_OPERATORS.items():
            if op in raw_bytes:
                findings.append(
                    Finding(
                        rule_id=f"SAVEDMODEL-{op.decode('ascii').upper()}-DETECTED",
                        title=f"Dangerous Operator {op.decode('ascii')} Detected in SavedModel Graph",
                        severity=RiskLevel.CRITICAL,
                        description=f"{desc} ({op.decode('ascii')})",
                        location=source_name,
                    )
                )
        return findings
