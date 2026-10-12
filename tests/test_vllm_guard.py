"""
Unit tests validating vLLM pre-flight model loading admission guard.
"""

import os
import shutil
import tempfile
import unittest

from admission_gate.vllm_guard import vLLMAdmissionGuard


class TestvLLMAdmissionGuard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.guard = vLLMAdmissionGuard()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_safe_safetensors_admitted(self):
        # Use existing synthetic safe safetensors
        safe_file = "test_models/safe_model.safetensors"
        if not os.path.exists(safe_file):
            self.skipTest(f"{safe_file} not found")
        verdict = self.guard.evaluate_model_path(safe_file)
        self.assertTrue(verdict.admitted)
        self.assertIsNone(verdict.rejection_reason)

    def test_trojan_pickle_rejected(self):
        trojan_file = "test_models/trojan_print.pkl"
        if not os.path.exists(trojan_file):
            self.skipTest(f"{trojan_file} not found")
        verdict = self.guard.evaluate_model_path(trojan_file)
        self.assertFalse(verdict.admitted)
        self.assertIn("rejected", verdict.rejection_reason.lower())

    def test_strict_safetensors_rejects_bin(self):
        strict_guard = vLLMAdmissionGuard(require_safetensors_only=True)
        bin_path = os.path.join(self.temp_dir, "pytorch_model.bin")
        with open(bin_path, "wb") as f:
            f.write(b"dummy")

        verdict = strict_guard.evaluate_model_path(self.temp_dir)
        self.assertFalse(verdict.admitted)
        self.assertIn("Strict policy", verdict.rejection_reason)


if __name__ == "__main__":
    unittest.main()
