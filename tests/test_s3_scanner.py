"""
Unit tests for S3ModelScanner.
Validates S3 URI parsing, scheme validation, and memory-streamed model evaluation.
"""

import pickle
import pytest
from scanner.integrations.s3_scanner import S3ModelScanner
from test_models.generate_test_models import BenignPrintProbe


def test_s3_uri_parsing():
    uri = "s3://mlops-production-models/nlp/bert-base/pytorch_model.bin"
    bucket, key = S3ModelScanner.parse_s3_uri(uri)
    assert bucket == "mlops-production-models"
    assert key == "nlp/bert-base/pytorch_model.bin"


def test_s3_invalid_scheme():
    with pytest.raises(ValueError):
        S3ModelScanner.parse_s3_uri("https://s3.amazonaws.com/bucket/model.pkl")


def test_s3_stream_scan_trojan():
    scanner = S3ModelScanner()
    trojan_bytes = pickle.dumps(BenignPrintProbe(), protocol=4)
    eval_res = scanner.scan_s3_object_bytes("s3://bucket/trojan.pkl", trojan_bytes)

    assert eval_res.passed is False
    assert any("REDUCE" in f.rule_id for f in eval_res.findings)
