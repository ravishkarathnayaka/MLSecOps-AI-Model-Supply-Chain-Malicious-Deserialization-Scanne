"""
Unit tests validating remote download symbol rules and categorization.
"""

import unittest
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.download_rules import REMOTE_DOWNLOAD_CALLABLES, lookup_download_rule


class TestDownloadRules(unittest.TestCase):
    def test_urllib_rules_present(self):
        rule = lookup_download_rule("urllib.request", "urlopen")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.severity, RiskLevel.CRITICAL)
        self.assertEqual(rule.category, "remote_payload_download")

    def test_requests_rules_present(self):
        rule = lookup_download_rule("requests", "get")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.severity, RiskLevel.HIGH)

    def test_benign_symbol_returns_none(self):
        rule = lookup_download_rule("torch.nn", "Linear")
        self.assertIsNone(rule)

    def test_all_rules_have_descriptions(self):
        for key, rule in REMOTE_DOWNLOAD_CALLABLES.items():
            self.assertTrue(len(rule.description) > 10, f"Rule {key} missing proper description")


if __name__ == "__main__":
    unittest.main()
