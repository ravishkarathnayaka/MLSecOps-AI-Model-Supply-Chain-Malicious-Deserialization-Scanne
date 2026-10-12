"""
Unit tests for ModelDiffScanner.
Validates differential security audits between baseline and candidate models.
"""

from scanner.core.diff_scanner import ModelDiffScanner


def test_diff_scanner_clean_models():
    diff_scanner = ModelDiffScanner()
    base_file = "test_models/safe_model.safetensors"
    cand_file = "test_models/safe_model.pkl"

    report = diff_scanner.compare_models(base_file, cand_file)
    assert report.regression_detected is False
    assert len(report.new_findings) == 0


def test_diff_scanner_regression_detected():
    diff_scanner = ModelDiffScanner()
    base_file = "test_models/safe_model.pkl"
    cand_file = "test_models/trojan_print.pkl"

    report = diff_scanner.compare_models(base_file, cand_file)
    assert report.regression_detected is True
    assert len(report.new_findings) > 0
    assert any("REDUCE" in f.rule_id for f in report.new_findings)
