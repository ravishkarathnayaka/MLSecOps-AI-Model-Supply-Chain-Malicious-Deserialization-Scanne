"""
Unit tests validating ONNX computation graph inspection, operator domain verification,
and external data reference path traversal detection.
"""

import pytest

from scanner.analyzers.onnx_analyzer import ONNXAnalyzer, ProtobufReader
from scanner.rules.dangerous_symbols import RiskLevel


def encode_varint(value: int) -> bytes:
    res = bytearray()
    while True:
        towrite = value & 0x7F
        value >>= 7
        if value:
            res.append(towrite | 0x80)
        else:
            res.append(towrite)
            break
    return bytes(res)


def make_proto_field(tag: int, wire_type: int, payload: bytes) -> bytes:
    tag_byte = (tag << 3) | wire_type
    if wire_type == 2:
        return encode_varint(tag_byte) + encode_varint(len(payload)) + payload
    elif wire_type == 0:
        return encode_varint(tag_byte) + payload
    return encode_varint(tag_byte) + payload


def build_minimal_onnx(node_name: str, op_type: str, domain: str, opset_domain: str = "ai.onnx") -> bytes:
    # NodeProto: tag 3=name, tag 4=op_type, tag 7=domain
    node_bytes = (
        make_proto_field(3, 2, node_name.encode("utf-8"))
        + make_proto_field(4, 2, op_type.encode("utf-8"))
        + make_proto_field(7, 2, domain.encode("utf-8"))
    )

    # GraphProto: tag 1=node, tag 2=name ("graph")
    graph_bytes = make_proto_field(2, 2, b"test_graph") + make_proto_field(1, 2, node_bytes)

    # Opset: tag 1=domain, tag 2=version (14)
    opset_bytes = make_proto_field(1, 2, opset_domain.encode("utf-8")) + make_proto_field(2, 0, encode_varint(14))

    # ModelProto: tag 1=ir_version (8), tag 7=graph, tag 8=opset_import
    return (
        make_proto_field(1, 0, encode_varint(8))
        + make_proto_field(7, 2, graph_bytes)
        + make_proto_field(8, 2, opset_bytes)
    )


def test_onnx_safe_standard_graph():
    analyzer = ONNXAnalyzer()
    raw = build_minimal_onnx(node_name="relu1", op_type="Relu", domain="ai.onnx", opset_domain="ai.onnx")
    findings = analyzer.analyze_bytes(raw, source_name="safe_onnx_model.onnx")

    assert len(findings) == 0


def test_onnx_untrusted_domain():
    analyzer = ONNXAnalyzer()
    raw = build_minimal_onnx(
        node_name="custom_layer",
        op_type="MyCustomOp",
        domain="untrusted.thirdparty.domain",
        opset_domain="untrusted.thirdparty.domain",
    )
    findings = analyzer.analyze_bytes(raw, source_name="untrusted_domain.onnx")

    assert len(findings) >= 1
    domain_findings = [f for f in findings if "DOMAIN" in f.rule_id]
    assert len(domain_findings) >= 1
    assert any(f.rule_id == "ONNX-UNTRUSTED-OPERATOR-DOMAIN" for f in findings)


def test_onnx_suspicious_operator_type():
    analyzer = ONNXAnalyzer()
    raw = build_minimal_onnx(
        node_name="exec_node",
        op_type="ExecutePayload",
        domain="ai.onnx",
        opset_domain="ai.onnx",
    )
    findings = analyzer.analyze_bytes(raw, source_name="suspicious_op.onnx")

    assert len(findings) >= 1
    crit_ops = [f for f in findings if f.rule_id == "ONNX-SUSPICIOUS-OPERATOR-TYPE"]
    assert len(crit_ops) == 1
    assert crit_ops[0].severity == RiskLevel.CRITICAL


def test_onnx_external_data_traversal():
    analyzer = ONNXAnalyzer()

    # Build StringStringEntryProto: tag 1=key ("location"), tag 2=value ("../../etc/shadow")
    entry_bytes = make_proto_field(1, 2, b"location") + make_proto_field(2, 2, b"../../etc/shadow")

    # TensorProto: tag 8=name ("weights_tensor"), tag 14=data_location (1=EXTERNAL), tag 13=external_data
    tensor_bytes = (
        make_proto_field(8, 2, b"weights_tensor")
        + make_proto_field(14, 0, encode_varint(1))
        + make_proto_field(13, 2, entry_bytes)
    )

    # GraphProto: tag 5=initializer
    graph_bytes = make_proto_field(2, 2, b"graph") + make_proto_field(5, 2, tensor_bytes)

    # ModelProto
    model_bytes = (
        make_proto_field(1, 0, encode_varint(8))
        + make_proto_field(7, 2, graph_bytes)
        + make_proto_field(8, 2, make_proto_field(1, 2, b"ai.onnx") + make_proto_field(2, 0, encode_varint(14)))
    )

    findings = analyzer.analyze_bytes(model_bytes, source_name="traversal.onnx")
    assert len(findings) >= 1
    traversal_findings = [f for f in findings if f.rule_id == "ONNX-EXTERNAL-DATA-TRAVERSAL"]
    assert len(traversal_findings) == 1
    assert traversal_findings[0].severity == RiskLevel.CRITICAL
