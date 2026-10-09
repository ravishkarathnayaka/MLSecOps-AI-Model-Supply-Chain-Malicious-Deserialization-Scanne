"""
ONNX Graph Static Analyzer.
Inspects ONNX computation graphs for unauthorized custom domains, untrusted operator sets,
external tensor reference path traversal risks, and suspicious code-execution operator patterns.
Supports both native onnx library (if installed) and a built-in zero-dependency Protobuf wire decoder.
"""

import os
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding

STANDARD_ONNX_DOMAINS: Set[str] = {
    "",  # Default domain is empty string in ONNX specification
    "ai.onnx",
    "ai.onnx.ml",
    "ai.onnx.preview.training",
}

# Suspicious operator types known in adversarial graph injection or arbitrary execution
SUSPICIOUS_OP_TYPES: Set[str] = {
    "PyOp",
    "PythonOp",
    "CustomOp",
    "ExecutePayload",
    "RunShell",
    "System",
    "Eval",
}


class ProtobufReader:
    """Zero-dependency Protocol Buffers wire format parser for ONNX ModelProto."""

    @staticmethod
    def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return result, offset
            shift += 7
        return result, offset

    @classmethod
    def parse_fields(cls, data: bytes) -> Dict[int, List[Any]]:
        """Parses a protobuf message into a dictionary mapping field tag to list of values."""
        fields: Dict[int, List[Any]] = {}
        offset = 0
        data_len = len(data)

        while offset < data_len:
            tag_and_type, offset = cls.read_varint(data, offset)
            tag = tag_and_type >> 3
            wire_type = tag_and_type & 0x07

            if wire_type == 0:  # Varint
                val, offset = cls.read_varint(data, offset)
            elif wire_type == 1:  # 64-bit
                if offset + 8 > data_len:
                    break
                val = struct.unpack("<Q", data[offset : offset + 8])[0]
                offset += 8
            elif wire_type == 2:  # Length-delimited (string, bytes, sub-message)
                length, offset = cls.read_varint(data, offset)
                if offset + length > data_len:
                    val = data[offset:]
                    offset = data_len
                else:
                    val = data[offset : offset + length]
                    offset += length
            elif wire_type == 5:  # 32-bit
                if offset + 4 > data_len:
                    break
                val = struct.unpack("<I", data[offset : offset + 4])[0]
                offset += 4
            else:
                # Unsupported or deprecated wire types (3, 4)
                break

            fields.setdefault(tag, []).append(val)

        return fields


class ONNXAnalyzer:
    """
    Static security analyzer for ONNX (.onnx) models.
    Traverses graph nodes, operators, and external tensor references without executing graph runtimes.
    """

    def __init__(
        self,
        allowed_domains: Optional[Set[str]] = None,
        strict_mode: bool = False,
    ):
        self.allowed_domains = allowed_domains if allowed_domains is not None else set(STANDARD_ONNX_DOMAINS)
        self.strict_mode = strict_mode

    def analyze(self, file_path: str) -> List[Finding]:
        if not os.path.exists(file_path):
            return [
                Finding(
                    rule_id="ONNX-FILE-NOT-FOUND",
                    title="ONNX Model File Not Found",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Specified model path does not exist: {file_path}",
                    location=file_path,
                )
            ]

        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self.analyze_bytes(data, source_name=file_path)
        except Exception as e:
            return [
                Finding(
                    rule_id="ONNX-FILE-READ-ERROR",
                    title="Failed to Read ONNX File",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Error reading ONNX file {file_path}: {str(e)}",
                    location=file_path,
                    details={"error": str(e)},
                )
            ]

    def analyze_bytes(self, data: bytes, source_name: str = "model.onnx") -> List[Finding]:
        findings: List[Finding] = []

        if len(data) < 4:
            findings.append(
                Finding(
                    rule_id="ONNX-CORRUPTED-FILE",
                    title="ONNX File Under Minimum Length",
                    severity=RiskLevel.HIGH,
                    category="format_validation",
                    description="File too small to constitute a valid ONNX ModelProto binary.",
                    location=source_name,
                )
            )
            return findings

        # First try native onnx library if present
        try:
            import onnx

            model = onnx.load_model_from_string(data)
            return self._analyze_native_onnx(model, source_name)
        except ImportError:
            # Fallback to zero-dependency Protobuf wire parser
            pass
        except Exception as ex:
            findings.append(
                Finding(
                    rule_id="ONNX-DECODE-ERROR",
                    title="Failed to Decode ONNX Model",
                    severity=RiskLevel.HIGH,
                    category="parsing_error",
                    description=f"ONNX protobuf deserialization failed: {str(ex)}",
                    location=source_name,
                )
            )
            return findings

        # Parse using built-in Protobuf wire reader
        try:
            return self._analyze_protobuf_wire(data, source_name)
        except Exception as ex:
            findings.append(
                Finding(
                    rule_id="ONNX-PARSE-EXCEPTION",
                    title="Error Parsing ONNX Protobuf Structure",
                    severity=RiskLevel.HIGH,
                    category="parsing_error",
                    description=f"Wire decoder error during ONNX analysis: {str(ex)}",
                    location=source_name,
                )
            )
            return findings

    def _analyze_native_onnx(self, model: Any, source_name: str) -> List[Finding]:
        findings: List[Finding] = []

        # Check opset imports
        for opset in model.opset_import:
            domain = opset.domain
            if domain not in self.allowed_domains:
                findings.append(
                    Finding(
                        rule_id="ONNX-UNRECOGNIZED-OPSET-DOMAIN",
                        title=f"Unrecognized ONNX Opset Domain: '{domain}'",
                        severity=RiskLevel.HIGH,
                        category="untrusted_domain",
                        description=(
                            f"Model imports opset with non-standard domain '{domain}' (version {opset.version}). "
                            "Untrusted custom domains may load unvetted operator binaries."
                        ),
                        location=f"{source_name}::opset_import",
                        details={"domain": domain, "version": opset.version},
                    )
                )

        # Traverse Graph Nodes
        if hasattr(model, "graph"):
            self._inspect_graph_nodes_native(model.graph, source_name, findings)

        return findings

    def _inspect_graph_nodes_native(self, graph: Any, source_name: str, findings: List[Finding]) -> None:
        for node in graph.node:
            node_name = node.name or "unnamed_node"
            op_type = node.op_type
            domain = node.domain or ""
            loc = f"{source_name}::node[{node_name}]"

            # Check domain
            if domain not in self.allowed_domains:
                findings.append(
                    Finding(
                        rule_id="ONNX-UNTRUSTED-OPERATOR-DOMAIN",
                        title=f"Untrusted Operator Domain '{domain}' in Node '{node_name}'",
                        severity=RiskLevel.HIGH,
                        category="untrusted_operator",
                        description=(
                            f"Node '{node_name}' of type '{op_type}' belongs to untrusted domain '{domain}'. "
                            "Rejecting custom or non-standard operator domains."
                        ),
                        location=loc,
                        details={"node": node_name, "op_type": op_type, "domain": domain},
                    )
                )

            # Check suspicious op types
            if op_type in SUSPICIOUS_OP_TYPES:
                findings.append(
                    Finding(
                        rule_id="ONNX-SUSPICIOUS-OPERATOR-TYPE",
                        title=f"Potentially Malicious Operator Type '{op_type}'",
                        severity=RiskLevel.CRITICAL,
                        category="arbitrary_execution",
                        description=(
                            f"Node '{node_name}' invokes suspicious operator type '{op_type}' "
                            "frequently associated with code execution or custom dynamic hooks."
                        ),
                        location=loc,
                        details={"node": node_name, "op_type": op_type},
                    )
                )

        # Check external tensor initializers
        for init in graph.initializer:
            if hasattr(init, "data_location") and init.data_location == 1:  # EXTERNAL
                for prop in getattr(init, "external_data", []):
                    if prop.key == "location":
                        loc_path = prop.value
                        if ".." in loc_path or loc_path.startswith("/") or loc_path.startswith("\\"):
                            findings.append(
                                Finding(
                                    rule_id="ONNX-EXTERNAL-DATA-TRAVERSAL",
                                    title="Path Traversal in ONNX External Tensor Data",
                                    severity=RiskLevel.CRITICAL,
                                    category="path_traversal",
                                    description=(
                                        f"Tensor '{init.name}' references external file path '{loc_path}' "
                                        "containing path traversal characters."
                                    ),
                                    location=f"{source_name}::initializer[{init.name}]",
                                    details={"external_location": loc_path},
                                )
                            )

    def _analyze_protobuf_wire(self, data: bytes, source_name: str) -> List[Finding]:
        """Parses ONNX ModelProto using raw protobuf wire deserializer."""
        findings: List[Finding] = []
        model_fields = ProtobufReader.parse_fields(data)

        # tag 8 = opset_import (repeated OperatorSetIdProto)
        for opset_bytes in model_fields.get(8, []):
            if isinstance(opset_bytes, bytes):
                opset_fields = ProtobufReader.parse_fields(opset_bytes)
                domain_bytes = opset_fields.get(1, [b""])[0]
                domain = domain_bytes.decode("utf-8", errors="ignore") if isinstance(domain_bytes, bytes) else ""
                version = opset_fields.get(2, [0])[0]

                if domain not in self.allowed_domains:
                    findings.append(
                        Finding(
                            rule_id="ONNX-UNRECOGNIZED-OPSET-DOMAIN",
                            title=f"Unrecognized ONNX Opset Domain: '{domain}'",
                            severity=RiskLevel.HIGH,
                            category="untrusted_domain",
                            description=(
                                f"Model imports opset with non-standard domain '{domain}' (version {version}). "
                                "Untrusted custom domains may load unvetted operator binaries."
                            ),
                            location=f"{source_name}::opset_import",
                            details={"domain": domain, "version": version},
                        )
                    )

        # tag 7 = graph (GraphProto)
        for graph_bytes in model_fields.get(7, []):
            if isinstance(graph_bytes, bytes):
                self._inspect_graph_wire(graph_bytes, source_name, findings)

        return findings

    def _inspect_graph_wire(self, graph_bytes: bytes, source_name: str, findings: List[Finding]) -> None:
        graph_fields = ProtobufReader.parse_fields(graph_bytes)

        # tag 1 = node (repeated NodeProto)
        for node_bytes in graph_fields.get(1, []):
            if not isinstance(node_bytes, bytes):
                continue

            node_fields = ProtobufReader.parse_fields(node_bytes)
            name_b = node_fields.get(3, [b""])[0]
            op_b = node_fields.get(4, [b""])[0]
            domain_b = node_fields.get(7, [b""])[0]

            node_name = name_b.decode("utf-8", errors="ignore") if isinstance(name_b, bytes) else "unnamed_node"
            op_type = op_b.decode("utf-8", errors="ignore") if isinstance(op_b, bytes) else "unknown_op"
            domain = domain_b.decode("utf-8", errors="ignore") if isinstance(domain_b, bytes) else ""

            loc = f"{source_name}::node[{node_name}]"

            # Check domain
            if domain not in self.allowed_domains:
                findings.append(
                    Finding(
                        rule_id="ONNX-UNTRUSTED-OPERATOR-DOMAIN",
                        title=f"Untrusted Operator Domain '{domain}' in Node '{node_name}'",
                        severity=RiskLevel.HIGH,
                        category="untrusted_operator",
                        description=(
                            f"Node '{node_name}' of type '{op_type}' belongs to untrusted domain '{domain}'. "
                            "Rejecting custom or non-standard operator domains."
                        ),
                        location=loc,
                        details={"node": node_name, "op_type": op_type, "domain": domain},
                    )
                )

            # Check operator
            if op_type in SUSPICIOUS_OP_TYPES:
                findings.append(
                    Finding(
                        rule_id="ONNX-SUSPICIOUS-OPERATOR-TYPE",
                        title=f"Potentially Malicious Operator Type '{op_type}'",
                        severity=RiskLevel.CRITICAL,
                        category="arbitrary_execution",
                        description=(
                            f"Node '{node_name}' invokes suspicious operator type '{op_type}' "
                            "frequently associated with code execution or custom dynamic hooks."
                        ),
                        location=loc,
                        details={"node": node_name, "op_type": op_type},
                    )
                )

        # tag 5 = initializer (repeated TensorProto)
        for init_bytes in graph_fields.get(5, []):
            if not isinstance(init_bytes, bytes):
                continue
            init_fields = ProtobufReader.parse_fields(init_bytes)
            name_b = init_fields.get(8, [b""])[0]  # tag 8 = name in TensorProto
            tensor_name = name_b.decode("utf-8", errors="ignore") if isinstance(name_b, bytes) else "tensor"

            # tag 14 = data_location (1 = EXTERNAL)
            data_loc = init_fields.get(14, [0])[0]
            if data_loc == 1:
                # tag 13 = external_data (repeated StringStringEntryProto: tag 1=key, tag 2=value)
                for entry_bytes in init_fields.get(13, []):
                    if isinstance(entry_bytes, bytes):
                        entry_fields = ProtobufReader.parse_fields(entry_bytes)
                        k_b = entry_fields.get(1, [b""])[0]
                        v_b = entry_fields.get(2, [b""])[0]
                        key = k_b.decode("utf-8", errors="ignore") if isinstance(k_b, bytes) else ""
                        val = v_b.decode("utf-8", errors="ignore") if isinstance(v_b, bytes) else ""
                        if key == "location" and (".." in val or val.startswith("/") or val.startswith("\\")):
                            findings.append(
                                Finding(
                                    rule_id="ONNX-EXTERNAL-DATA-TRAVERSAL",
                                    title="Path Traversal in ONNX External Tensor Data",
                                    severity=RiskLevel.CRITICAL,
                                    category="path_traversal",
                                    description=(
                                        f"Tensor '{tensor_name}' references external file path '{val}' "
                                        "containing path traversal characters."
                                    ),
                                    location=f"{source_name}::initializer[{tensor_name}]",
                                    details={"external_location": val},
                                )
                            )
