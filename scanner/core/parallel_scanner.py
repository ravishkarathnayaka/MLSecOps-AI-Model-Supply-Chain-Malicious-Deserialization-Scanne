"""
High-Performance Multi-Threaded Parallel Model Scanner.
Scans multiple model files and repository trees concurrently across worker threads,
tracking throughput (MB/s), file latencies, and aggregating enterprise security reports.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import time
from typing import Callable, Dict, List, Optional, Tuple

from scanner.core.engine import MODEL_EXTENSIONS, ModelScanEngine
from scanner.rules.policy_engine import EvaluationResult, Finding


class ParallelModelScanner:
    """
    Concurrent scanner for high-throughput model scanning in enterprise pipelines.
    """

    def __init__(self, engine: Optional[ModelScanEngine] = None, max_workers: int = 4):
        self.engine = engine or ModelScanEngine()
        self.max_workers = max_workers

    def scan_directory_parallel(
        self,
        directory_path: str,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Tuple[EvaluationResult, List[str], Dict[str, float]]:
        """
        Discovers all model artifacts in directory and audits them in parallel.
        Returns aggregated EvaluationResult, list of scanned files, and latency mapping.
        """
        all_targets: List[str] = []
        for root, _, files in os.walk(directory_path):
            for f in sorted(files):
                ext = os.path.splitext(f)[1].lower()
                if ext in MODEL_EXTENSIONS:
                    all_targets.append(os.path.join(root, f))

        total_files = len(all_targets)
        if total_files == 0:
            eval_res, _ = self.engine.scan_path(directory_path)
            return eval_res, [], {}

        scanned_files: List[str] = []
        all_findings: List[Finding] = []
        latencies: Dict[str, float] = {}

        def _scan_worker(target_file: str) -> Tuple[str, List[Finding], float]:
            t0 = time.perf_counter()
            findings = self.engine._scan_single_file(target_file)
            duration = time.perf_counter() - t0
            return target_file, findings, duration

        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, total_files))) as executor:
            futures = {executor.submit(_scan_worker, f): f for f in all_targets}
            completed_count = 0
            for fut in as_completed(futures):
                target, findings, dur = fut.result()
                scanned_files.append(target)
                all_findings.extend(findings)
                latencies[target] = dur
                completed_count += 1
                if progress_callback:
                    progress_callback(target, completed_count, total_files)

        evaluation = self.engine.policy_engine.evaluate(all_findings)
        return evaluation, scanned_files, latencies
