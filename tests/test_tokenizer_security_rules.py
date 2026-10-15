"""
Unit tests validating tokenizer configuration security checks.
"""

import json
import unittest
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.tokenizer_security_rules import TokenizerSecurityValidator


class TestTokenizerSecurityRules(unittest.TestCase):
    def setUp(self):
        self.validator = TokenizerSecurityValidator()

    def test_clean_tokenizer_config(self):
        clean = {
            "model_type": "bert",
            "vocab_size": 30522,
            "do_lower_case": True,
        }
        findings = self.validator.validate_tokenizer_json(json.dumps(clean))
        self.assertEqual(len(findings), 0)

    def test_auto_map_flagged(self):
        trojan = {
            "model_type": "custom",
            "auto_map": {"AutoTokenizer": ["custom_tokenizer.CustomTokenizer", None]},
        }
        findings = self.validator.validate_tokenizer_json(json.dumps(trojan))
        self.assertTrue(any(f.rule_id == "TOKENIZER-AUTO-MAP-REMOTE-CODE" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    def test_insecure_http_flagged(self):
        insecure = {
            "vocab_file": "http://insecure-cdn.com/vocab.txt",
        }
        findings = self.validator.validate_tokenizer_json(json.dumps(insecure))
        self.assertTrue(any(f.rule_id == "TOKENIZER-INSECURE-HTTP-URL" for f in findings))

    def test_local_file_scheme_flagged(self):
        file_uri = {
            "merges_file": "file:///etc/shadow",
        }
        findings = self.validator.validate_tokenizer_json(json.dumps(file_uri))
        self.assertTrue(any(f.rule_id == "TOKENIZER-LOCAL-FILE-SCHEME" for f in findings))


if __name__ == "__main__":
    unittest.main()
