"""
Unit tests validating CLI execution, SARIF v2.1.0 schema compliance for GitHub Code Scanning,
and admission gate HTTP endpoints.
"""

import json
import os
import sys
import pytest
from starlette.testclient import TestClient

from admission_gate.webhook_server import app
from cli.main import run_cli
from scanner.core.engine import ModelScanEngine
from scanner.core.reporter import Reporter
from scanner.rules.dangerous_symbols import RiskLevel


@pytest.fixture
def test_models_dir():
    return os.path.join(os.path.dirname(__file__), "..", "test_models")


def test_cli_clean_model_returns_zero(test_models_dir):
    safe_path = os.path.join(test_models_dir, "safe_model.safetensors")
    assert os.path.exists(safe_path)

    exit_code = run_cli(["--path", safe_path, "--format", "text", "--fail-on", "high"])
    assert exit_code == 0


def test_cli_malicious_model_returns_nonzero(test_models_dir):
    trojan_path = os.path.join(test_models_dir, "trojan_print.pkl")
    assert os.path.exists(trojan_path)

    exit_code = run_cli(["--path", trojan_path, "--format", "text", "--fail-on", "high"])
    assert exit_code == 1


def test_sarif_v210_schema_structure(test_models_dir, tmp_path):
    trojan_path = os.path.join(test_models_dir, "trojan_print.pkl")
    engine = ModelScanEngine(fail_on_threshold=RiskLevel.HIGH)
    evaluation, scanned_files = engine.scan_path(trojan_path)

    sarif_doc = Reporter.to_sarif(evaluation, scanned_files)

    # Validate OASIS SARIF v2.1.0 top-level requirements
    assert sarif_doc["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in sarif_doc["$schema"]
    assert "runs" in sarif_doc and len(sarif_doc["runs"]) == 1

    run = sarif_doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "MLSecOps-Scanner"
    assert len(run["tool"]["driver"]["rules"]) >= 1

    # Validate results mapping
    results = run["results"]
    assert len(results) >= 1
    assert any(r["ruleId"] == "ARBITRARY-CODE-EXECUTION-REDUCE" for r in results)

    first_res = results[0]
    assert "locations" in first_res
    assert len(first_res["locations"]) >= 1
    phys_loc = first_res["locations"][0]["physicalLocation"]
    assert "artifactLocation" in phys_loc
    assert "uri" in phys_loc["artifactLocation"]


def test_cli_sarif_file_export(test_models_dir, tmp_path):
    out_file = str(tmp_path / "scan_output.sarif")
    trojan_path = os.path.join(test_models_dir, "trojan_print.pkl")

    exit_code = run_cli([
        "--path", trojan_path,
        "--format", "sarif",
        "--output", out_file,
        "--fail-on", "high"
    ])

    assert exit_code == 1
    assert os.path.exists(out_file)

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) >= 1


def test_admission_webhook_endpoints(test_models_dir):
    client = TestClient(app)

    # Health check
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"

    # Review clean model -> Allowed
    safe_model = os.path.join(test_models_dir, "safe_model.safetensors")
    review_safe = client.post("/v1/admission/review", json={
        "model_uri": safe_model,
        "fail_on": "high",
        "include_sarif": True,
    })
    assert review_safe.status_code == 200
    res_json = review_safe.json()
    assert res_json["allowed"] is True
    assert res_json["verdict"] == "PASSED"
    assert res_json["sarif"] is not None

    # Review trojan model -> Blocked
    trojan_model = os.path.join(test_models_dir, "trojan_print.pkl")
    review_trojan = client.post("/v1/admission/review", json={
        "model_uri": trojan_model,
        "fail_on": "high",
    })
    assert review_trojan.status_code == 200
    res_trojan = review_trojan.json()
    assert res_trojan["allowed"] is False
    assert res_trojan["verdict"] == "FAILED"
    assert res_trojan["violations_count"] >= 1

    # Metrics
    metrics_resp = client.get("/metrics")
    assert metrics_resp.status_code == 200
    metrics_data = metrics_resp.json()
    assert metrics_data["total_scans"] >= 2
    assert metrics_data["allowed_models"] >= 1
    assert metrics_data["blocked_models"] >= 1
