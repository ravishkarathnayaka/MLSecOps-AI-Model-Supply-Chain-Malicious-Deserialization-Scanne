"""
Static security validator for Hugging Face Hub datasets and pipeline definitions.
Inspects YAML metadata, dataset loading scripts, and pipeline tags for trust_remote_code
and dynamic download vectors without downloading complete multi-gigabyte datasets.
"""

from typing import Any, Dict, List
import yaml

from scanner.core.reporter import Finding
from scanner.rules.dangerous_symbols import RiskLevel


class HFDatasetSecurityChecker:
    """Audits Hugging Face dataset cards (README.md) and dataset loading scripts."""

    def __init__(self, allow_remote_code: bool = False):
        self.allow_remote_code = allow_remote_code

    def check_readme_frontmatter(self, readme_content: str, repo_id: str = "hf-repo") -> List[Finding]:
        findings: List[Finding] = []
        if not readme_content.startswith("---"):
            return findings

        parts = readme_content.split("---", 2)
        if len(parts) < 3:
            return findings

        yaml_text = parts[1]
        try:
            meta = yaml.safe_load(yaml_text)
        except Exception:
            return findings

        if not isinstance(meta, dict):
            return findings

        # Check for configs requesting custom script execution
        configs = meta.get("configs", [])
        if isinstance(configs, list):
            for cfg in configs:
                if isinstance(cfg, dict) and cfg.get("data_files"):
                    files = str(cfg["data_files"])
                    if any(f in files.lower() for f in [".sh", ".exe", ".py"]):
                        findings.append(
                            Finding(
                                rule_id="HF-DATASET-EXECUTABLE-DATA-FILE",
                                title="Executable File Specified as Dataset Data Source",
                                severity=RiskLevel.HIGH,
                                description=f"Hugging Face dataset config specifies script as data source: {files}",
                                location=f"{repo_id}:README.md",
                                category="supply_chain_integrity",
                            )
                        )

        # Check for dangerous custom pipeline tags
        pipe_tag = meta.get("pipeline_tag", "")
        if "custom" in str(pipe_tag).lower():
            findings.append(
                Finding(
                    rule_id="HF-DATASET-CUSTOM-PIPELINE-TAG",
                    title="Custom Pipeline Tag Requiring Remote Code",
                    severity=RiskLevel.MEDIUM,
                    description=f"Dataset or model specifies custom pipeline tag: {pipe_tag}",
                    location=f"{repo_id}:README.md",
                    category="remote_code_execution",
                )
            )

        return findings

    def check_dataset_script(self, script_code: str, file_path: str = "dataset.py") -> List[Finding]:
        findings: List[Finding] = []
        dangerous_calls = ["os.system", "subprocess.Popen", "subprocess.call", "__import__", "eval("]
        for call in dangerous_calls:
            if call in script_code:
                findings.append(
                    Finding(
                        rule_id="HF-DATASET-SCRIPT-UNSAFE-CODE",
                        title=f"Unsafe Code Execution Call in HF Dataset Script ({call})",
                        severity=RiskLevel.CRITICAL,
                        description=f"Dataset processing script executes dangerous system API: {call}",
                        location=file_path,
                        category="arbitrary_code_execution",
                    )
                )
        return findings
