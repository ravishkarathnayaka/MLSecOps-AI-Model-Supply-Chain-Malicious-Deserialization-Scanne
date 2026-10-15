"""
Unit tests validating steganographic executable signature detection inside tensors.
"""

import unittest
from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.steganography_rules import scan_tensor_bytes_for_steganography


class TestSteganographyRules(unittest.TestCase):
    def test_clean_tensor_bytes(self):
        # 100 float32 zero/normal bytes
        clean = b"\x00\x00\x80\x3f" * 25
        findings = scan_tensor_bytes_for_steganography(clean, "weight.layer1")
        self.assertEqual(len(findings), 0)

    def test_embedded_elf_binary_flagged(self):
        # Steganographic payload with ELF header
        trojan = b"\x00" * 32 + b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64
        findings = scan_tensor_bytes_for_steganography(trojan, "bias.fc2")
        self.assertTrue(any(f.rule_id == "STEG-STEG-EMBEDDED-ELF" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    def test_embedded_zip_flagged(self):
        trojan = b"PK\x03\x04\x14\x00\x00\x00" + b"\x00" * 20
        findings = scan_tensor_bytes_for_steganography(trojan, "embedding.weight")
        self.assertTrue(any(f.rule_id == "STEG-STEG-EMBEDDED-ZIP" for f in findings))


if __name__ == "__main__":
    unittest.main()
