"""
Unit tests for EntropyAnalyzer.
Validates Shannon entropy calculations, sliding window chunking, and anomaly thresholds.
"""

import os
import pytest
from scanner.analyzers.entropy_analyzer import EntropyAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


def test_zero_entropy_homogeneous_bytes():
    analyzer = EntropyAnalyzer()
    null_bytes = b"\x00" * 4096
    entropy = analyzer.calculate_shannon_entropy(null_bytes)
    assert entropy == 0.0

    findings = analyzer.analyze_bytes(null_bytes)
    assert len(findings) == 0


def test_high_entropy_random_payload():
    analyzer = EntropyAnalyzer(high_threshold=7.8)
    random_bytes = os.urandom(8192)
    entropy = analyzer.calculate_shannon_entropy(random_bytes)
    assert entropy > 7.8

    findings = analyzer.analyze_bytes(random_bytes, source_name="random_payload.bin")
    assert len(findings) > 0
    assert findings[0].rule_id == "ENTROPY-ANOMALY-HIGH"
    assert findings[0].severity == RiskLevel.MEDIUM


def test_moderate_entropy_text_and_weights():
    analyzer = EntropyAnalyzer(high_threshold=7.9)
    # Structured repetitive weights/text have lower entropy
    text_data = b"LinearLayer weight bias " * 300
    entropy = analyzer.calculate_shannon_entropy(text_data)
    assert entropy < 5.0
    findings = analyzer.analyze_bytes(text_data)
    assert len(findings) == 0


def test_entropy_file_scan(tmp_path):
    analyzer = EntropyAnalyzer(high_threshold=7.8)
    test_file = tmp_path / "high_entropy.bin"
    test_file.write_bytes(os.urandom(6000))

    findings = analyzer.analyze_file(str(test_file))
    assert len(findings) == 1
    assert "Offset:" in findings[0].location
