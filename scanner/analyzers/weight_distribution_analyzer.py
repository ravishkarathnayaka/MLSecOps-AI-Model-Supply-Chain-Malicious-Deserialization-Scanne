"""
Statistical Weight Distribution and Backdoor Trigger Analyzer.
Analyzes floating-point tensor arrays for numerical anomalies:
NaN/Infinity corruption, extreme Trojan outlier magnitudes, and abnormal zero-sparsity.
Runs zero-dependency using Python's built-in math and struct modules.
"""

import math
import struct
from typing import List, Tuple

from scanner.rules.backdoor_heuristics import BACKDOOR_HEURISTIC_RULES, WeightAnomalyThresholds
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding


class WeightDistributionAnalyzer:
    """
    Statistical analyzer identifying backdoor triggers and numerical corruption in raw float weight buffers.
    """

    def __init__(self, thresholds: WeightAnomalyThresholds = WeightAnomalyThresholds()):
        self.thresholds = thresholds

    def analyze_float32_buffer(self, buffer_bytes: bytes, tensor_name: str = "tensor") -> List[Finding]:
        findings: List[Finding] = []
        num_floats = len(buffer_bytes) // 4
        if num_floats == 0:
            return findings

        nan_inf_count = 0
        extreme_outlier_count = 0
        zero_count = 0

        # Sample up to 100,000 floats for high-speed scanning
        step = max(1, num_floats // 50_000)
        sampled_values: List[float] = []

        for i in range(0, num_floats, step):
            val = struct.unpack("<f", buffer_bytes[i * 4 : (i + 1) * 4])[0]
            if math.isnan(val) or math.isinf(val):
                nan_inf_count += 1
            else:
                if abs(val) > self.thresholds.max_weight_magnitude:
                    extreme_outlier_count += 1
                if val == 0.0:
                    zero_count += 1
                sampled_values.append(val)

        total_sampled = len(sampled_values) + nan_inf_count

        # 1. NaN / Inf check
        if nan_inf_count > self.thresholds.max_nan_inf_count:
            sev, desc = BACKDOOR_HEURISTIC_RULES["WEIGHT-CORRUPTED-NAN-INF"]
            findings.append(
                Finding(
                    rule_id="WEIGHT-CORRUPTED-NAN-INF",
                    title=f"Corrupted NaN/Inf Parameters in Tensor '{tensor_name}'",
                    severity=sev,
                    category="numerical_integrity",
                    description=f"{desc} (Detected {nan_inf_count} invalid float elements).",
                    location=f"tensor::{tensor_name}",
                    details={"nan_inf_count": nan_inf_count},
                )
            )

        # 2. Extreme outlier magnitude
        if extreme_outlier_count > 0:
            sev, desc = BACKDOOR_HEURISTIC_RULES["WEIGHT-EXTREME-OUTLIER"]
            findings.append(
                Finding(
                    rule_id="WEIGHT-EXTREME-OUTLIER",
                    title=f"Extreme Weight Outlier in Tensor '{tensor_name}'",
                    severity=sev,
                    category="backdoor_heuristic",
                    description=f"{desc} (Detected {extreme_outlier_count} values exceeding magnitude {self.thresholds.max_weight_magnitude}).",
                    location=f"tensor::{tensor_name}",
                    details={"extreme_count": extreme_outlier_count},
                )
            )

        # 3. Abnormal zero sparsity
        if total_sampled > 1000 and (zero_count / total_sampled) > self.thresholds.max_zero_sparsity_ratio:
            sev, desc = BACKDOOR_HEURISTIC_RULES["WEIGHT-ABNORMAL-SPARSITY"]
            findings.append(
                Finding(
                    rule_id="WEIGHT-ABNORMAL-SPARSITY",
                    title=f"Abnormal Zero Sparsity in Tensor '{tensor_name}'",
                    severity=sev,
                    category="backdoor_heuristic",
                    description=f"{desc} (Zero ratio: {zero_count / total_sampled * 100:.1f}%).",
                    location=f"tensor::{tensor_name}",
                    details={"zero_ratio": zero_count / total_sampled},
                )
            )

        return findings
