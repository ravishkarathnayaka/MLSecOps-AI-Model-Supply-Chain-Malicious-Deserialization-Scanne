"""
Unit tests validating SLSA v1.0 in-toto statement envelope generation.
"""

import unittest
from scanner.provenance.slsa_generator import SLSAGenerator


class TestSLSAGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = SLSAGenerator()

    def test_generate_statement_structure(self):
        stmt = self.generator.generate_statement(
            model_name="bert-base-uncased.safetensors",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            source_repository="https://github.com/my-org/llm-training",
            commit_sha="a1b2c3d4e5f6",
            dependencies=[
                {"uri": "pkg:pypi/torch@2.1.0", "sha256": "1234abcd5678"},
            ],
        )

        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["predicateType"], "https://slsa.dev/provenance/v1")
        self.assertEqual(len(stmt["subject"]), 1)
        self.assertEqual(stmt["subject"][0]["name"], "bert-base-uncased.safetensors")
        self.assertEqual(stmt["subject"][0]["digest"]["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        pred = stmt["predicate"]
        self.assertEqual(pred["buildDefinition"]["externalParameters"]["sourceRepository"], "https://github.com/my-org/llm-training")
        self.assertEqual(len(pred["buildDefinition"]["resolvedDependencies"]), 1)
        self.assertEqual(pred["runDetails"]["builder"]["id"], "https://github.com/ravishkarathnayaka/MLSecOps")


if __name__ == "__main__":
    unittest.main()
