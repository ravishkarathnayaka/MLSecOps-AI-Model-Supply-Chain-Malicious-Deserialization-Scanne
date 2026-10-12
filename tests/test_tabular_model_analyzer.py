"""
Unit tests for TabularModelAnalyzer.
Validates inspection of XGBoost JSON and LightGBM model structures for embedded payloads and callbacks.
"""

import json
from scanner.analyzers.tabular_model_analyzer import TabularModelAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


def test_xgboost_clean_json(tmp_path):
    analyzer = TabularModelAnalyzer()
    clean_model = {
        "version": [1, 7, 0],
        "learner": {
            "objective": {"name": "binary:logistic"},
            "attributes": {"best_iteration": "10"},
        },
    }
    model_file = tmp_path / "model.json"
    model_file.write_text(json.dumps(clean_model))

    findings = analyzer.analyze_file(str(model_file))
    assert len(findings) == 0


def test_xgboost_embedded_pickle_attribute(tmp_path):
    analyzer = TabularModelAnalyzer()
    # "gAJ" prefix indicates base64 encoded Python 3 pickle opcode
    trojan_model = {
        "learner": {
            "attributes": {
                "scikit_learn": "gAJjYnVpbHRpbnMKcHJpbnQKcQAoWA=="
            }
        }
    }
    model_file = tmp_path / "trojan_xgb.json"
    model_file.write_text(json.dumps(trojan_model))

    findings = analyzer.analyze_file(str(model_file))
    assert any(f.rule_id == "XGBOOST-EMBEDDED-PICKLE-ATTRIBUTE" for f in findings)
    assert any(f.severity == RiskLevel.CRITICAL for f in findings)


def test_lightgbm_injected_code(tmp_path):
    analyzer = TabularModelAnalyzer()
    lgb_content = "Tree=0\nnum_leaves=31\nexec('import socket; ...')\n"
    model_file = tmp_path / "model.txt"
    model_file.write_text(lgb_content)

    findings = analyzer.analyze_file(str(model_file))
    assert any(f.rule_id == "LIGHTGBM-SUSPICIOUS-CODE-INJECTION" for f in findings)
