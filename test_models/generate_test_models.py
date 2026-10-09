"""
Synthetic Test Model Generator.
Programmatically generates safe reference models and harmless non-destructive test artifacts
to validate static detection engines without executing untrusted weights.
"""

import json
import os
import pickle
import struct
import sys
import zipfile


class BenignPrintProbe:
    """Harmless test class using __reduce__ with builtins.print to verify opcode detection."""

    def __reduce__(self):
        return (print, ("Safe Test Payload - Deserialization Inspection Triggered",))


def encode_varint(value: int) -> bytes:
    """Encodes an integer into protobuf varint bytes."""
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
    if wire_type == 2:  # length-delimited
        return encode_varint(tag_byte) + encode_varint(len(payload)) + payload
    elif wire_type == 0:  # varint
        return encode_varint(tag_byte) + payload
    return encode_varint(tag_byte) + payload


def generate_safe_safetensors(output_path: str) -> None:
    """Generates a fully compliant standard Safetensors model."""
    # 2 tensors of F32: [2, 2] -> 4 floats = 16 bytes each
    tensor1_bytes = b"\x00" * 16
    tensor2_bytes = b"\x01" * 16
    buffer_bytes = tensor1_bytes + tensor2_bytes

    header_dict = {
        "weight_1": {
            "dtype": "F32",
            "shape": [2, 2],
            "data_offsets": [0, 16],
        },
        "weight_2": {
            "dtype": "F32",
            "shape": [2, 2],
            "data_offsets": [16, 32],
        },
        "__metadata__": {
            "framework": "pytorch",
            "format": "safetensors",
            "description": "Benign synthetic test model",
        },
    }

    header_str = json.dumps(header_dict, separators=(",", ":"))
    header_bytes = header_str.encode("utf-8")
    header_len = len(header_bytes)

    with open(output_path, "wb") as f:
        f.write(struct.pack("<Q", header_len))
        f.write(header_bytes)
        f.write(buffer_bytes)


def generate_malformed_safetensors(output_path: str) -> None:
    """Generates a malformed Safetensors model with out-of-bounds offsets."""
    header_dict = {
        "weight_oob": {
            "dtype": "F32",
            "shape": [2, 2],
            "data_offsets": [0, 999999],  # Out of bounds!
        }
    }
    header_bytes = json.dumps(header_dict).encode("utf-8")
    header_len = len(header_bytes)
    dummy_buffer = b"\x00" * 16

    with open(output_path, "wb") as f:
        f.write(struct.pack("<Q", header_len))
        f.write(header_bytes)
        f.write(dummy_buffer)


def generate_safe_pickle(output_path: str) -> None:
    """Generates a safe pickle file containing standard numeric primitives."""
    safe_data = {
        "model_name": "synthetic-resnet-safe",
        "epoch": 10,
        "weights": [0.1, 0.2, 0.3, 0.4, 0.5],
        "config": {"hidden_size": 256, "layers": 4},
    }
    with open(output_path, "wb") as f:
        pickle.dump(safe_data, f, protocol=4)


def generate_trojan_pickle(output_path: str) -> None:
    """Generates a synthetic harmless trojan pickle containing builtins.print probe."""
    probe = BenignPrintProbe()
    with open(output_path, "wb") as f:
        pickle.dump(probe, f, protocol=4)


def generate_safe_pytorch_pt(output_path: str) -> None:
    """Generates a safe PyTorch ZIP archive (.pt) containing benign weights."""
    safe_pickle_bytes = pickle.dumps({"layer.weight": [1.0, 2.0, 3.0]}, protocol=4)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/version", "3\n")
        zf.writestr("archive/byteorder", "little\n")
        zf.writestr("archive/data.pkl", safe_pickle_bytes)


def generate_trojan_pytorch_pt(output_path: str) -> None:
    """Generates a PyTorch ZIP archive (.pt) bundling a benign probe in data.pkl."""
    trojan_pickle_bytes = pickle.dumps(BenignPrintProbe(), protocol=4)
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("archive/version", "3\n")
        zf.writestr("archive/byteorder", "little\n")
        zf.writestr("archive/data.pkl", trojan_pickle_bytes)


def generate_safe_onnx(output_path: str) -> None:
    """Generates a compliant minimal ONNX ModelProto using standard 'ai.onnx' domain."""
    # NodeProto: tag 3=name ("relu_node"), tag 4=op_type ("Relu"), tag 7=domain ("ai.onnx")
    node_bytes = (
        make_proto_field(3, 2, b"relu_node")
        + make_proto_field(4, 2, b"Relu")
        + make_proto_field(7, 2, b"ai.onnx")
    )

    # GraphProto: tag 1=node, tag 2=name ("safe_graph")
    graph_bytes = make_proto_field(2, 2, b"safe_graph") + make_proto_field(1, 2, node_bytes)

    # Opset: tag 1=domain ("ai.onnx"), tag 2=version (14)
    opset_bytes = make_proto_field(1, 2, b"ai.onnx") + make_proto_field(2, 0, encode_varint(14))

    # ModelProto: tag 1=ir_version (8), tag 7=graph, tag 8=opset_import
    model_bytes = (
        make_proto_field(1, 0, encode_varint(8))
        + make_proto_field(7, 2, graph_bytes)
        + make_proto_field(8, 2, opset_bytes)
    )

    with open(output_path, "wb") as f:
        f.write(model_bytes)


def generate_custom_op_onnx(output_path: str) -> None:
    """Generates an ONNX model with an unauthorized custom operator domain and op_type."""
    # NodeProto: custom.adversarial domain and ExecutePayload op_type
    node_bytes = (
        make_proto_field(3, 2, b"suspicious_node")
        + make_proto_field(4, 2, b"ExecutePayload")
        + make_proto_field(7, 2, b"custom.adversarial")
    )

    graph_bytes = make_proto_field(2, 2, b"adversarial_graph") + make_proto_field(1, 2, node_bytes)
    opset_bytes = make_proto_field(1, 2, b"custom.adversarial") + make_proto_field(2, 0, encode_varint(1))

    model_bytes = (
        make_proto_field(1, 0, encode_varint(8))
        + make_proto_field(7, 2, graph_bytes)
        + make_proto_field(8, 2, opset_bytes)
    )

    with open(output_path, "wb") as f:
        f.write(model_bytes)


def generate_all_test_models(target_dir: str = "test_models") -> None:
    """Generates all synthetic test models in the target directory."""
    os.makedirs(target_dir, exist_ok=True)
    print(f"Generating synthetic test models in '{target_dir}'...")

    models = [
        ("safe_model.safetensors", generate_safe_safetensors),
        ("malformed.safetensors", generate_malformed_safetensors),
        ("safe_model.pkl", generate_safe_pickle),
        ("trojan_print.pkl", generate_trojan_pickle),
        ("safe_model.pt", generate_safe_pytorch_pt),
        ("trojan_print.pt", generate_trojan_pytorch_pt),
        ("safe_model.onnx", generate_safe_onnx),
        ("custom_op.onnx", generate_custom_op_onnx),
    ]

    for fname, generator_fn in models:
        fpath = os.path.join(target_dir, fname)
        generator_fn(fpath)
        size = os.path.getsize(fpath)
        print(f"  [+] Generated {fname} ({size} bytes)")

    print("Synthetic test suite model generation completed successfully.\n")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    current_dir = os.path.dirname(os.path.abspath(__file__))
    generate_all_test_models(target_dir=current_dir)

