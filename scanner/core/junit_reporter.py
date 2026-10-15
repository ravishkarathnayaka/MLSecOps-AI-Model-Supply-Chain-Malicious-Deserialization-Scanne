"""
JUnit XML Test Report Generator.
Renders standard JUnit XML compatible with GitHub Actions, Jenkins, and GitLab CI test dashboards.
"""

from typing import List
import xml.etree.ElementTree as ET

from scanner.rules.policy_engine import EvaluationResult


class JUnitReporter:
    """Generates JUnit XML test report documents from scan evaluations."""

    @classmethod
    def generate_junit_xml(cls, evaluation: EvaluationResult, scanned_files: List[str]) -> str:
        total_tests = len(scanned_files)
        failures_count = len(evaluation.violations)

        testsuites = ET.Element("testsuites", name="MLSecOps-Model-Scan")
        testsuite = ET.SubElement(
            testsuites,
            "testsuite",
            name="ModelSecurityInspection",
            tests=str(total_tests),
            failures=str(failures_count),
            errors="0",
        )

        # Map findings by location
        findings_by_loc = {}
        for f in evaluation.findings:
            loc = f.location.split(":")[0]
            findings_by_loc.setdefault(loc, []).append(f)

        for file_path in scanned_files:
            tc = ET.SubElement(
                testsuite,
                "testcase",
                classname="mlsecops.model_inspection",
                name=file_path,
            )
            file_findings = findings_by_loc.get(file_path, [])
            for f in file_findings:
                if f.severity.value in ("CRITICAL", "HIGH"):
                    failure = ET.SubElement(
                        tc,
                        "failure",
                        message=f"{f.rule_id}: {f.description}",
                        type=f.severity.value,
                    )
                    failure.text = f"Rule: {f.rule_id}\nSeverity: {f.severity.value}\nLocation: {f.location}\nDescription: {f.description}"

        return ET.tostring(testsuites, encoding="utf-8", xml_declaration=True).decode("utf-8")
