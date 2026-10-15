"""
Unit tests validating Intel OpenVINO IR static XML and buffer security inspection.
"""

import unittest
from scanner.analyzers.openvino_analyzer import OpenVINOIRAnalyzer
from scanner.rules.dangerous_symbols import RiskLevel


class TestOpenVINOIRAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = OpenVINOIRAnalyzer()

    def test_clean_openvino_xml(self):
        clean_xml = """<net name="clean_net" version="10">
            <layers>
                <layer id="0" name="input" type="Parameter">
                    <data shape="1,3,224,224" element_type="f32"/>
                </layer>
                <layer id="1" name="conv1" type="Convolution">
                    <data offset="0" size="1024"/>
                </layer>
            </layers>
        </net>"""
        findings = self.analyzer.analyze_xml_content(clean_xml, bin_size_bytes=2048, source_name="model.xml")
        self.assertEqual(len(findings), 0)

    def test_xxe_payload_detected(self):
        xxe_xml = """<?xml version="1.0"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <net name="test" version="10">
            <layers><layer id="0" name="xxe" type="Const"/></layers>
        </net>"""
        findings = self.analyzer.analyze_xml_content(xxe_xml, source_name="xxe.xml")
        self.assertTrue(any(f.rule_id == "OPENVINO-XXE-INJECTION-RISK" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    def test_custom_layer_flagged(self):
        custom_xml = """<net name="test" version="10">
            <layers>
                <layer id="0" name="evil_hook" type="Custom"/>
            </layers>
        </net>"""
        findings = self.analyzer.analyze_xml_content(custom_xml, source_name="custom.xml")
        self.assertTrue(any(f.rule_id == "OPENVINO-CUSTOM-LAYER-CUSTOM" for f in findings))

    def test_buffer_boundary_overflow_detected(self):
        overflow_xml = """<net name="test" version="10">
            <layers>
                <layer id="0" name="weights" type="Const">
                    <data offset="5000" size="2000"/>
                </layer>
            </layers>
        </net>"""
        # Bin size is only 1000 bytes, offset+size is 7000 bytes -> overflow!
        findings = self.analyzer.analyze_xml_content(overflow_xml, bin_size_bytes=1000, source_name="overflow.xml")
        self.assertTrue(any(f.rule_id == "OPENVINO-WEIGHT-BUFFER-OVERFLOW" for f in findings))
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)


if __name__ == "__main__":
    unittest.main()
