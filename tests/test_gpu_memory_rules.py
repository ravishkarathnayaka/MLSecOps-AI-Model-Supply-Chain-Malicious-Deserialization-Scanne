"""
Unit tests validating GPU kernel memory manipulation rules.
"""

import unittest
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.gpu_memory_rules import lookup_gpu_memory_rule, GPU_MEMORY_RULES


class TestGPUMemoryRules(unittest.TestCase):
    def test_ctypes_memmove_rule(self):
        rule = lookup_gpu_memory_rule("ctypes", "memmove")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.severity, RiskLevel.CRITICAL)
        self.assertEqual(rule.category, "gpu_memory_manipulation")

    def test_cupy_memcpy_rule(self):
        rule = lookup_gpu_memory_rule("cupy.cuda.runtime", "memcpy")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.severity, RiskLevel.CRITICAL)

    def test_safe_symbol_returns_none(self):
        rule = lookup_gpu_memory_rule("torch", "randn")
        self.assertIsNone(rule)

    def test_all_rules_valid(self):
        for k, r in GPU_MEMORY_RULES.items():
            self.assertTrue(r.description)
            self.assertIn(r.severity, [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM])


if __name__ == "__main__":
    unittest.main()
