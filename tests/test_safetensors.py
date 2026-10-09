"""
Unit tests validating Safetensors header JSON schema parsing, buffer boundary checks,
and zero-executable memory guarantees.
"""

import json
import struct
import pytest

from scanner.analyzers.safetensors_checker import SafetensorsChecker
from scanner.rules.dangerous_symbols import RiskLevel


def create_safetensors_bytes(header_dict: dict, data_buffer: bytes) -> bytes:
    header_bytes = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
    header_len = len(header_bytes)
    return struct.pack("<Q", header_len) + header_bytes + data_buffer


def test_safetensors_valid_model():
    checker = SafetensorsChecker()
    # 2 tensors of F32 [2, 2] -> 16 bytes each
    buffer = b"\x00" * 32
    header = {
        "weight_a": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
        "weight_b": {"dtype": "F32", "shape": [2, 2], "data_offsets": [16, 32]},
        "__metadata__": {"format": "pt", "author": "researcher"},
    }
    raw = create_safetensors_bytes(header, buffer)
    findings = checker.check_bytes(raw, source_name="valid.safetensors")

    assert len(findings) == 0


def test_safetensors_buffer_out_of_bounds():
    checker = SafetensorsChecker()
    buffer = b"\x00" * 16
    header = {
        "weight_overflow": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 99999]},
    }
    raw = create_safetensors_bytes(header, buffer)
    findings = checker.check_bytes(raw, source_name="overflow.safetensors")

    assert len(findings) >= 1
    oob_findings = [f for f in findings if f.rule_id == "SAFETENSORS-BUFFER-OUT-OF-BOUNDS"]
    assert len(oob_findings) == 1
    assert oob_findings[0].severity == RiskLevel.CRITICAL


def test_safetensors_byte_length_mismatch():
    checker = SafetensorsChecker()
    # Declared shape [2, 2] of F32 requires 16 bytes, but offsets specify only 8 bytes
    buffer = b"\x00" * 8
    header = {
        "mismatched_weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 8]},
    }
    raw = create_safetensors_bytes(header, buffer)
    findings = checker.check_bytes(raw, source_name="mismatch.safetensors")

    assert len(findings) >= 1
    mismatch_findings = [f for f in findings if f.rule_id == "SAFETENSORS-TENSOR-SIZE-MISMATCH"]
    assert len(mismatch_findings) == 1
    assert mismatch_findings[0].severity == RiskLevel.HIGH


def test_safetensors_unrecognized_dtype():
    checker = SafetensorsChecker()
    buffer = b"\x00" * 16
    header = {
        "bad_dtype_weight": {"dtype": "UNKNOWN_DTYPE_XYZ", "shape": [2, 2], "data_offsets": [0, 16]},
    }
    raw = create_safetensors_bytes(header, buffer)
    findings = checker.check_bytes(raw, source_name="bad_dtype.safetensors")

    assert len(findings) >= 1
    dtype_findings = [f for f in findings if f.rule_id == "SAFETENSORS-UNRECOGNIZED-DTYPE"]
    assert len(dtype_findings) == 1


def test_safetensors_malformed_json_header():
    checker = SafetensorsChecker()
    invalid_json_bytes = b'{"weight": {"dtype": "F32", broken_json'
    raw = struct.pack("<Q", len(invalid_json_bytes)) + invalid_json_bytes + b"\x00" * 16

    findings = checker.check_bytes(raw, source_name="corrupt.safetensors")
    assert len(findings) >= 1
    assert any(f.rule_id == "SAFETENSORS-HEADER-INVALID-JSON" for f in findings)


def test_safetensors_truncated_file():
    checker = SafetensorsChecker()
    raw = b"\x01\x02\x03"  # Less than 8 bytes
    findings = checker.check_bytes(raw, source_name="truncated.safetensors")

    assert len(findings) >= 1
    assert any(f.rule_id == "SAFETENSORS-TRUNCATED-FILE" for f in findings)


def test_safetensors_suspicious_metadata_payload():
    checker = SafetensorsChecker()
    buffer = b"\x00" * 16
    header = {
        "weight_a": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
        "__metadata__": {
            "comment": "__reduce__ injection attempt",
            "hook": "os.system('id')",
        },
    }
    raw = create_safetensors_bytes(header, buffer)
    findings = checker.check_bytes(raw, source_name="injection.safetensors")

    assert len(findings) >= 1
    payload_findings = [f for f in findings if f.rule_id == "SAFETENSORS-SUSPICIOUS-METADATA-PAYLOAD"]
    assert len(payload_findings) >= 1
