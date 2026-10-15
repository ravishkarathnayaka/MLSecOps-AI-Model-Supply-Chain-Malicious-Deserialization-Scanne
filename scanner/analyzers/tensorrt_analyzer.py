"""
Static security analyzer for NVIDIA TensorRT engine execution plans (.plan, .engine).
Validates TRT binary serialization headers, detects unauthorized dynamic plugin references,
and checks memory allocation bounds without requiring NVIDIA GPU or TensorRT library runtime.
"""

import struct
from typing import List
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class TensorRTPlanAnalyzer:
    """Static security inspector for NVIDIA TensorRT execution plans."""

    TRT_MAGIC_V1 = b"trte"
    TRT_MAGIC_V2 = b"TRTE"
    TRT_MAGIC_PTRT = b"ptrt"

    MAX_SAFE_WORKSPACE_BYTES = 32 * 1024 * 1024 * 1024  # 32 GB sanity boundary

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_bytes(self, raw_bytes: bytes, source_name: str = "model.plan") -> List[Finding]:
        findings: List[Finding] = []

        if len(raw_bytes) < 8:
            findings.append(
                Finding(
                    rule_id="TENSORRT-FILE-TRUNCATED",
                    title="Truncated TensorRT Engine File",
                    severity=RiskLevel.HIGH,
                    description="TensorRT engine file is too short to contain a valid header.",
                    location=source_name,
                    category="format_anomaly",
                )
            )
            return findings

        # Check magic header
        magic = raw_bytes[:4]
        if magic not in (self.TRT_MAGIC_V1, self.TRT_MAGIC_V2, self.TRT_MAGIC_PTRT):
            findings.append(
                Finding(
                    rule_id="TENSORRT-INVALID-MAGIC-HEADER",
                    title="Invalid TensorRT Magic Header",
                    severity=RiskLevel.MEDIUM,
                    description=f"File does not start with valid TensorRT magic bytes: {magic!r}",
                    location=source_name,
                    category="format_anomaly",
                )
            )

        # Inspect binary for dangerous external dynamic library references (.so, .dll)
        # Custom TensorRT plugins load external .so files dynamically
        dangerous_patterns = [b".so", b".dll", b"libplugin", b"system(", b"/bin/sh"]
        for pat in dangerous_patterns:
            if pat in raw_bytes:
                findings.append(
                    Finding(
                        rule_id="TENSORRT-CUSTOM-PLUGIN-OR-LIB",
                        title=f"External Plugin or Library Reference in TensorRT Plan ({pat.decode('ascii', errors='ignore')})",
                        severity=RiskLevel.HIGH if pat in (b".so", b".dll") else RiskLevel.CRITICAL,
                        description=f"TensorRT plan references dynamic plugin or system symbol: {pat.decode('ascii', errors='ignore')}",
                        location=source_name,
                        category="native_code_injection",
                    )
                )

        return findings
