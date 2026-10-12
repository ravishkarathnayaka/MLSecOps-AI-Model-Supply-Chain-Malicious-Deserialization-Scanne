"""
Unit tests for GCSModelScanner.
Validates Google Cloud Storage gs:// URI parsing and streamed model inspection.
"""

import pickle
import pytest
from scanner.integrations.gcs_scanner import GCSModelScanner
from test_models.generate_test_models import BenignPrintProbe


def test_gcs_uri_parsing():
    uri = "gs://vertex-ai-models-bucket/vision/resnet50/model.safetensors"
    bucket, path = GCSModelScanner.parse_gcs_uri(uri)
    assert bucket == "vertex-ai-models-bucket"
    assert path == "vision/resnet50/model.safetensors"


def test_gcs_invalid_scheme():
    with pytest.raises(ValueError):
        GCSModelScanner.parse_gcs_uri("s3://wrong-scheme-bucket/model.pkl")


def test_gcs_stream_scan():
    scanner = GCSModelScanner()
    trojan_bytes = pickle.dumps(BenignPrintProbe(), protocol=4)
    eval_res = scanner.scan_gcs_object_bytes("gs://gcp-bucket/trojan.pt", trojan_bytes)

    assert eval_res.passed is False
    assert any("REDUCE" in f.rule_id for f in eval_res.findings)
