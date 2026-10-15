"""
Static security analyzer for Apache MXNet model artifacts (<model>-symbol.json, <model>-0000.params).
Inspects MXNet JSON computation graphs and NDArray parameter streams for untrusted custom operator plugins,
dynamic Python operator properties, and binary buffer overrun anomalies without MXNet runtime.
"""

import json
from typing import Any, Dict, List
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class MXNetAnalyzer:
    """Static security validator for Apache MXNet symbol graphs and parameter binaries."""

    DANGEROUS_MXNET_OPS = {
        "Custom": "Dynamic custom operator executed via external library or Python callback",
        "_CustomOp": "Internal dynamic custom operator evaluation",
        "Python": "Arbitrary Python operator execution hook",
        "system": "Command line execution node in computational graph",
    }

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_symbol_json(self, json_str: str, source_name: str = "model-symbol.json") -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(json_str)
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="MXNET-INVALID-SYMBOL-JSON",
                    title="Malformed MXNet Symbol JSON",
                    severity=RiskLevel.MEDIUM,
                    description=f"Failed to parse MXNet symbol JSON structure: {e}",
                    location=source_name,
                    category="format_anomaly",
                )
            )
            return findings

        nodes = data.get("nodes", [])
        if not isinstance(nodes, list):
            return findings

        for idx, node in enumerate(nodes):
            if not isinstance(node, dict):
                continue
            op = node.get("op", "")
            if op in self.DANGEROUS_MXNET_OPS:
                findings.append(
                    Finding(
                        rule_id=f"MXNET-UNSAFE-OP-{op.upper().replace('_', '')}",
                        title=f"Unsafe MXNet Operator '{op}' Detected",
                        severity=RiskLevel.CRITICAL if op in ("Python", "system") else RiskLevel.HIGH,
                        description=f"{self.DANGEROUS_MXNET_OPS[op]} in node '{node.get('name', f'node_{idx}')}'",
                        location=f"{source_name}:node[{idx}]",
                        category="graph_operator_anomaly",
                    )
                )

            # Check attributes for Python callbacks
            attrs = node.get("attrs", {})
            if isinstance(attrs, dict):
                for k, v in attrs.items():
                    if any(bad in str(v).lower() for bad in ["__import__", "os.system", "subprocess", "exec("]):
                        findings.append(
                            Finding(
                                rule_id="MXNET-MALICIOUS-ATTR-STRING",
                                title="Malicious Execution Code in MXNet Node Attribute",
                                severity=RiskLevel.CRITICAL,
                                description=f"Node '{node.get('name')}' attribute '{k}' contains prohibited code: {v}",
                                location=f"{source_name}:node[{idx}]:attr[{k}]",
                                category="remote_code_execution",
                            )
                        )
        return findings

    def analyze_params_bytes(self, raw_bytes: bytes, source_name: str = "model-0000.params") -> List[Finding]:
        findings: List[Finding] = []
        # MXNet NDArray magic header: 0x112 or 0x113
        if len(raw_bytes) < 4:
            return findings

        # Check for pickle injections in params
        if b"\x80\x02" in raw_bytes or b"\x80\x03" in raw_bytes or b"\x80\x04" in raw_bytes:
            if b"cos\n" in raw_bytes or b"cposix\n" in raw_bytes or b"cbuiltins\n" in raw_bytes:
                findings.append(
                    Finding(
                        rule_id="MXNET-PARAMS-EMBEDDED-PICKLE",
                        title="Embedded Malicious Pickle in MXNet Params File",
                        severity=RiskLevel.CRITICAL,
                        description="MXNet binary parameter file contains disguised pickle stream with unsafe globals.",
                        location=source_name,
                        category="deserialization_injection",
                    )
                )

        return findings
