"""
Multi-Threaded Parallel Model Scanning Worker Pool.
Accelerates bulk repository scanning across multi-sharded transformer model directories.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from typing import Dict, List, Optional, Tuple

from scanner.core.engine import ModelScanEngine
from scanner.rules.policy_engine import EvaluationResult, Finding, PolicyEngine


class ParallelModelScanner:
    """Orchestrates multi-threaded static model inspections across directories."""

    def __init__(self, max_workers: int = 4, engine: Optional[ModelScanEngine] = None):
        self.max_workers = max_workers
        self.engine = engine or ModelScanEngine()
        self.policy_engine = PolicyEngine()

    def scan_files(self, file_paths: List[str]) -> Tuple[EvaluationResult, List[str]]:
        """Scans list of model files in parallel using worker threads."""
        all_findings: List[Finding] = []
        scanned_files: List[str] = []

        def worker(file_path: str) -> Tuple[str, List[Finding]]:
            eval_res, _ = self.engine.scan_path(file_path)
            return file_path, eval_res.findings

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {executor.submit(worker, fp): fp for fp in file_paths}
            for future in as_completed(future_to_file):
                fp, findings = future.result()
                scanned_files.append(fp)
                all_findings.extend(findings)

        combined_eval = self.policy_engine.evaluate(all_findings)
        return combined_eval, scanned_files
