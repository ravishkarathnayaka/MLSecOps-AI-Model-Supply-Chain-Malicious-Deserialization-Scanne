"""
Unit tests validating MITRE ATLAS threat taxonomy enrichment on scanner findings.
"""

import unittest
from scanner.core.atlas_mapper import MITREATLASMapper
from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class TestATLASMapper(unittest.TestCase):
    def test_enrich_deserialization_finding(self):
        finding = Finding(
            rule_id="ARBITRARY-CODE-EXECUTION-REDUCE",
            title="Pickle __reduce__ Code Execution",
            severity=RiskLevel.CRITICAL,
            description="Malicious opcode payload",
            location="model.pkl",
            category="deserialization_injection",
        )
        MITREATLASMapper.enrich_finding(finding)
        self.assertIn("mitre_atlas", finding.details)
        atlas = finding.details["mitre_atlas"]
        self.assertEqual(atlas["id"], "AML.T0010")
        self.assertEqual(atlas["tactic"], "Initial Access")

    def test_enrich_prompt_injection_finding(self):
        finding = Finding(
            rule_id="LLM-INJECTION-IGNORE-INSTRUCTIONS",
            title="Prompt Injection",
            severity=RiskLevel.HIGH,
            description="Ignore instructions pattern",
            location="chat_template",
            category="prompt_injection_backdoor",
        )
        MITREATLASMapper.enrich_finding(finding)
        atlas = finding.details["mitre_atlas"]
        self.assertEqual(atlas["id"], "AML.T0043")

    def test_enrich_fallback_general(self):
        finding = Finding(
            rule_id="CUSTOM-RULE",
            title="Custom Rule",
            severity=RiskLevel.LOW,
            description="Custom note",
            location="file.txt",
            category="unknown_category",
        )
        MITREATLASMapper.enrich_finding(finding)
        self.assertIn("mitre_atlas", finding.details)


if __name__ == "__main__":
    unittest.main()
