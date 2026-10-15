"""
Static security analyzer for Baidu PaddlePaddle model artifacts (.pdmodel, .pdparams, .pdopt).
Inspects Paddle protobuf graph definitions and serialized weight stores for custom execution kernels,
embedded pickle opcodes, and unauthorized execution callbacks without Paddle runtime.
"""

from typing import List
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class PaddlePaddleAnalyzer:
    """Static security validator for PaddlePaddle model and parameter files."""

    SUSPICIOUS_PADDLE_OPS = {
        b"py_func": "Executes arbitrary Python function inside Paddle execution graph",
        b"custom_op": "Unverified custom C++ kernel execution",
        b"c_allreduce_max": "Distributed communication hook with potential unauthorized socket binding",
        b"system_call": "Direct system call invocation inside computational graph",
    }

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_bytes(self, raw_bytes: bytes, source_name: str = "model.pdmodel") -> List[Finding]:
        findings: List[Finding] = []

        if not raw_bytes:
            return findings

        # 1. Check for legacy embedded pickle payloads inside .pdparams
        if b"\x80\x02" in raw_bytes or b"\x80\x03" in raw_bytes or b"\x80\x04" in raw_bytes or b"\x80\x05" in raw_bytes:
            if b"cbuiltins" in raw_bytes or b"cos\n" in raw_bytes or b"cposix\n" in raw_bytes or b"csubprocess\n" in raw_bytes:
                findings.append(
                    Finding(
                        rule_id="PADDLE-EMBEDDED-PICKLE-INJECTION",
                        title="Embedded Malicious Pickle in PaddlePaddle Artifact",
                        severity=RiskLevel.CRITICAL,
                        description="PaddlePaddle weight file contains embedded pickle stream invoking forbidden globals.",
                        location=source_name,
                        category="deserialization_injection",
                    )
                )

        # 2. Check for dangerous operators in protobuf graph (.pdmodel)
        for op, desc in self.SUSPICIOUS_PADDLE_OPS.items():
            if op in raw_bytes:
                findings.append(
                    Finding(
                        rule_id=f"PADDLE-UNSAFE-OP-{op.decode('ascii').upper().replace('_', '-')}",
                        title=f"Unsafe Operator '{op.decode('ascii')}' Detected in Paddle Model",
                        severity=RiskLevel.CRITICAL if b"py_func" in op or b"system" in op else RiskLevel.HIGH,
                        description=f"{desc} (Op: {op.decode('ascii')})",
                        location=source_name,
                        category="graph_operator_anomaly",
                    )
                )

        # 3. Path traversal sequences
        if b"../" in raw_bytes or b"..\\" in raw_bytes:
            findings.append(
                Finding(
                    rule_id="PADDLE-PATH-TRAVERSAL-DETECTED",
                    title="Path Traversal Sequence in Paddle Weight Descriptor",
                    severity=RiskLevel.HIGH,
                    description="Relative directory traversal sequence detected in model resource references.",
                    location=source_name,
                    category="path_traversal",
                )
            )

        return findings
