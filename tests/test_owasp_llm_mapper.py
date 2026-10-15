"""
Unit tests validating OWASP Top 10 for LLM classification on scanner findings.
"""

import unittest
from scanner.core.owasp_llm_mapper import OWASPLLMMapper
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class TestOWASPLLMMapper(unittest.TestCase):
    def test_enrich_prompt_injection(self):
        f = Finding(
            rule_id="LLM-INJECTION-TEST",
            title="Prompt Injection",
            severity=RiskLevel.HIGH,
            description="Testing LLM01 mapping",
            location="template",
            category="prompt_injection_backdoor",
        )
        OWASPLLMMapper.enrich_finding(f)
        self.assertIn("owasp_llm", f.details)
        self.assertEqual(f.details["owasp_llm"]["id"], "LLM01")

    def test_enrich_supply_chain(self):
        f = Finding(
            rule_id="ARBITRARY-CODE-EXECUTION",
            title="Pickle Injection",
            severity=RiskLevel.CRITICAL,
            description="Testing LLM05 mapping",
            location="model.pkl",
            category="deserialization_injection",
        )
        OWASPLLMMapper.enrich_finding(f)
        self.assertEqual(f.details["owasp_llm"]["id"], "LLM05")

    def test_enrich_compute_hijacking(self):
        f = Finding(
            rule_id="HIJACK-TEST",
            title="Miner Injection",
            severity=RiskLevel.CRITICAL,
            description="Testing LLM04 DoS mapping",
            location="script.py",
            category="compute_hijacking",
        )
        OWASPLLMMapper.enrich_finding(f)
        self.assertEqual(f.details["owasp_llm"]["id"], "LLM04")


if __name__ == "__main__":
    unittest.main()
