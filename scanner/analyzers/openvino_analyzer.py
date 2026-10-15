"""
Static security analyzer for Intel OpenVINO Intermediate Representation models (.xml, .bin).
Detects XML External Entity (XXE) injections, custom untrusted extension layers,
and buffer boundary overflow offsets without requiring OpenVINO runtime libraries.
"""

import re
from typing import List, Optional
import xml.etree.ElementTree as ET

from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class OpenVINOIRAnalyzer:
    """Static security validator for Intel OpenVINO XML network topology and weights."""

    UNTRUSTED_LAYER_TYPES = {"Custom", "ExperimentalDetectron", "PyOp", "ExternalExecution"}

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    def analyze_xml_content(
        self,
        xml_content: str,
        bin_size_bytes: Optional[int] = None,
        source_name: str = "model.xml",
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Check for XML External Entity (XXE) Injection
        if "<!DOCTYPE" in xml_content or "<!ENTITY" in xml_content:
            findings.append(
                Finding(
                    rule_id="OPENVINO-XXE-INJECTION-RISK",
                    title="XML External Entity (XXE) Payload Detected in OpenVINO IR",
                    severity=RiskLevel.CRITICAL,
                    description="OpenVINO XML file contains DOCTYPE/ENTITY declarations risking XXE file read or SSRF.",
                    location=source_name,
                    category="xml_vulnerability",
                )
            )

        # 2. Defensively parse XML topology without expanding entities
        try:
            # Strip DOCTYPE for safe local parsing if testing
            safe_xml = re.sub(r"<!DOCTYPE[^>]*>", "", xml_content, flags=re.IGNORECASE)
            root = ET.fromstring(safe_xml)
        except Exception as e:
            findings.append(
                Finding(
                    rule_id="OPENVINO-MALFORMED-XML",
                    title="Malformed OpenVINO Topology XML",
                    severity=RiskLevel.MEDIUM,
                    description=f"Failed to parse XML topology tree: {e}",
                    location=source_name,
                    category="format_anomaly",
                )
            )
            return findings

        # 3. Traverse layers for untrusted custom layers
        for layer in root.iter("layer"):
            layer_type = layer.attrib.get("type", "")
            layer_name = layer.attrib.get("name", "unnamed")
            if layer_type in self.UNTRUSTED_LAYER_TYPES:
                findings.append(
                    Finding(
                        rule_id=f"OPENVINO-CUSTOM-LAYER-{layer_type.upper()}",
                        title=f"Untrusted Custom Layer '{layer_type}' in OpenVINO Graph",
                        severity=RiskLevel.HIGH,
                        description=f"Layer '{layer_name}' uses unverified custom type '{layer_type}'.",
                        location=f"{source_name}:layer[{layer_name}]",
                        category="graph_operator_anomaly",
                    )
                )

        # 4. If bin size provided, check buffer boundaries
        if bin_size_bytes is not None:
            for layer in root.iter("layer"):
                for data_node in layer.iter("data"):
                    offset = data_node.attrib.get("offset")
                    size = data_node.attrib.get("size")
                    if offset is not None and size is not None:
                        try:
                            off_val = int(offset)
                            sz_val = int(size)
                            if off_val + sz_val > bin_size_bytes:
                                findings.append(
                                    Finding(
                                        rule_id="OPENVINO-WEIGHT-BUFFER-OVERFLOW",
                                        title="Weight Buffer Boundary Overflow in OpenVINO IR",
                                        severity=RiskLevel.CRITICAL,
                                        description=f"Layer offset ({off_val}) + size ({sz_val}) exceeds weights file ({bin_size_bytes}).",
                                        location=source_name,
                                        category="memory_safety",
                                    )
                                )
                                break
                        except ValueError:
                            pass

        return findings
