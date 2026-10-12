"""
Unit tests for WeightDistributionAnalyzer.
Validates detection of NaN/Inf corruption, extreme outlier spikes, and abnormal sparsity.
"""

import struct
from scanner.analyzers.weight_distribution_analyzer import WeightDistributionAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


def test_weight_distribution_clean():
    analyzer = WeightDistributionAnalyzer()
    # 100 normal float32 values around standard normal distribution
    clean_floats = [0.05 * (i % 10) for i in range(500)]
    buf = struct.pack(f"<{len(clean_floats)}f", *clean_floats)

    findings = analyzer.analyze_float32_buffer(buf, tensor_name="layer1.weight")
    assert len(findings) == 0


def test_weight_distribution_nan_inf_flagged():
    analyzer = WeightDistributionAnalyzer()
    floats_with_nan = [0.1, 0.2, float("nan"), 0.4, float("inf")]
    buf = struct.pack(f"<{len(floats_with_nan)}f", *floats_with_nan)

    findings = analyzer.analyze_float32_buffer(buf, tensor_name="corrupted.weight")
    assert any(f.rule_id == "WEIGHT-CORRUPTED-NAN-INF" for f in findings)
    assert any(f.severity == RiskLevel.HIGH for f in findings)


def test_weight_distribution_extreme_outlier_flagged():
    analyzer = WeightDistributionAnalyzer()
    outlier_floats = [0.1] * 100 + [1e9]  # 1e9 exceeds max magnitude
    buf = struct.pack(f"<{len(outlier_floats)}f", *outlier_floats)

    findings = analyzer.analyze_float32_buffer(buf, tensor_name="trojan.weight")
    assert any(f.rule_id == "WEIGHT-EXTREME-OUTLIER" for f in findings)


def test_weight_distribution_sparsity_flagged():
    analyzer = WeightDistributionAnalyzer()
    # 2000 zero floats
    sparse_floats = [0.0] * 2000
    buf = struct.pack(f"<{len(sparse_floats)}f", *sparse_floats)

    findings = analyzer.analyze_float32_buffer(buf, tensor_name="sparse.weight")
    assert any(f.rule_id == "WEIGHT-ABNORMAL-SPARSITY" for f in findings)
