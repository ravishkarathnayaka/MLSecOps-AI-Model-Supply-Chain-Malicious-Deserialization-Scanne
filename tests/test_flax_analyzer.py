"""
Unit tests validating JAX/Flax msgpack checkpoint static security analysis.
"""

import unittest
from scanner.analyzers.flax_analyzer import FlaxMsgpackAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


class TestFlaxMsgpackAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = FlaxMsgpackAnalyzer()

    def test_clean_flax_checkpoint(self):
        # Benign msgpack map: {"params": {"dense": [1, 2, 3]}}
        clean_bytes = b"\x81\xa6params\x81\xa5dense\x93\x01\x02\x03"
        findings = self.analyzer.analyze_bytes(clean_bytes, "model.msgpack")
        self.assertEqual(len(findings), 0)

    def test_embedded_pickle_detected(self):
        # Byte sequence with pickle magic and dangerous os.system global
        malicious = b"\x80\x04cos\nsystem\n(X\x06\x00\x00\x00whoami\x85R."
        findings = self.analyzer.analyze_bytes(malicious, "trojan.flax")
        self.assertTrue(any(f.rule_id == "FLAX-EMBEDDED-PICKLE-PAYLOAD" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    def test_embedded_shell_command_detected(self):
        payload = b"\x81\xa6config\xa9/bin/bash -i"
        findings = self.analyzer.analyze_bytes(payload, "backdoor.msgpack")
        self.assertTrue(any(f.rule_id == "FLAX-EMBEDDED-SHELL-STRING" for f in findings))

    def test_msgpack_extension_flagged(self):
        # 0xd4 is fixext 1
        payload = b"\x81\xa4item\xd4\x01\x42"
        findings = self.analyzer.analyze_bytes(payload, "ext.msgpack")
        self.assertTrue(any(f.rule_id == "FLAX-CUSTOM-EXT-TYPE" for f in findings))


if __name__ == "__main__":
    unittest.main()
