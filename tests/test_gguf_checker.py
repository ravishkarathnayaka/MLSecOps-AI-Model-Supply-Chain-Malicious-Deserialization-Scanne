"""
Unit tests for GGUFChecker.
Validates GGUF v2/v3 header parsing, magic verification, and metadata anomaly detection.
"""

import struct
from scanner.analyzers.gguf_checker import GGUFChecker
from scanner.rules.dangerous_symbols import RiskLevel


def test_gguf_truncated():
    checker = GGUFChecker()
    findings = checker.check_bytes(b"GGUF\x02\x00", source_name="short.gguf")
    assert len(findings) == 1
    assert findings[0].rule_id == "GGUF-TRUNCATED-HEADER"


def test_gguf_invalid_magic():
    checker = GGUFChecker()
    # 24 bytes with wrong magic
    bad_data = b"BADM" + struct.pack("<IQQ", 3, 10, 5)
    findings = checker.check_bytes(bad_data, source_name="bad_magic.gguf")
    assert len(findings) == 1
    assert findings[0].rule_id == "GGUF-INVALID-MAGIC"


def test_gguf_unsupported_version():
    checker = GGUFChecker()
    # Magic GGUF, version 99
    data = b"GGUF" + struct.pack("<IQQ", 99, 10, 5)
    findings = checker.check_bytes(data, source_name="version99.gguf")
    assert len(findings) == 1
    assert findings[0].rule_id == "GGUF-UNSUPPORTED-VERSION"


def test_gguf_valid_header():
    checker = GGUFChecker()
    # Magic GGUF, version 3, 20 tensors, 0 KV pairs
    valid_data = b"GGUF" + struct.pack("<IQQ", 3, 20, 0)
    findings = checker.check_bytes(valid_data, source_name="valid.gguf")
    assert len(findings) == 0


def test_gguf_suspicious_metadata_key():
    checker = GGUFChecker()
    # Header: magic GGUF, version 3, 10 tensors, 1 KV pair
    header = b"GGUF" + struct.pack("<IQQ", 3, 10, 1)
    # KV pair: key "custom_eval_payload", type 8 (string)
    key_name = b"custom_eval_payload"
    kv_data = struct.pack("<Q", len(key_name)) + key_name + struct.pack("<I", 8)
    data = header + kv_data

    findings = checker.check_bytes(data, source_name="suspicious.gguf")
    assert any(f.rule_id == "GGUF-SUSPICIOUS-METADATA-KEY" for f in findings)
