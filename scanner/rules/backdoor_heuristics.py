"""
Adversarial Trojan and Backdoor Weight Distribution Heuristic Rules.
Defines statistical threshold rules for detecting poisoned weights,
Trojan triggers, extreme gradient outliers, and abnormal sparsity.
"""

from dataclasses import dataclass
from scanner.rules.dangerous_symbols import RiskLevel


@dataclass(frozen=True)
class WeightAnomalyThresholds:
    max_weight_magnitude: float = 1e5  # Extreme floating point weights
    z_score_outlier_limit: float = 6.0  # Statistical outlier threshold for Trojan neurons
    max_zero_sparsity_ratio: float = 0.995  # Suspicious complete zero clustering
    max_nan_inf_count: int = 0  # Zero tolerance for corrupted NaN / Inf parameters


BACKDOOR_HEURISTIC_RULES = {
    "WEIGHT-EXTREME-OUTLIER": (
        RiskLevel.MEDIUM,
        "Statistical weight outlier detected. Neuron magnitude exceeds 6.0 standard deviations.",
    ),
    "WEIGHT-CORRUPTED-NAN-INF": (
        RiskLevel.HIGH,
        "Corrupted parameter detected containing NaN (Not a Number) or Inf (Infinity).",
    ),
    "WEIGHT-ABNORMAL-SPARSITY": (
        RiskLevel.LOW,
        "Anomalously high zero-sparsity ratio (>99.5%) detected in weight matrix.",
    ),
}
