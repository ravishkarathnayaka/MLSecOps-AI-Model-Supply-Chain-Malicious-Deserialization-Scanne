"""
Real-time Directory Watch Daemon for MLSecOps CLI.
Monitors filesystem directories for newly staged model artifacts and immediately invokes
static inspection engines to prevent untrusted weights from being loaded by inference servers.
"""

import os
import time
from typing import Callable, Dict, List, Optional, Set

from scanner.core.engine import ModelScanEngine
from scanner.rules.policy_engine import EvaluationResult


class ModelDirectoryWatcher:
    """Watches model directory and triggers automated security scans upon new file creation."""

    SUPPORTED_EXTENSIONS = {".pt", ".pth", ".pkl", ".pickle", ".bin", ".onnx", ".safetensors", ".msgpack"}

    def __init__(
        self,
        watch_path: str,
        on_scan_callback: Optional[Callable[[str, EvaluationResult], None]] = None,
        scan_engine: Optional[ModelScanEngine] = None,
    ):
        self.watch_path = watch_path
        self.on_scan = on_scan_callback
        self.engine = scan_engine or ModelScanEngine()
        self._known_files: Dict[str, float] = {}

    def poll_once(self) -> List[Tuple[str, EvaluationResult]]:
        """Scans directory once for new or modified files, returning new scan results."""
        results: List[Tuple[str, EvaluationResult]] = []
        if not os.path.exists(self.watch_path):
            return results

        current_files: Dict[str, float] = {}
        for root, _, files in os.walk(self.watch_path):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in self.SUPPORTED_EXTENSIONS:
                    full_p = os.path.join(root, f)
                    try:
                        mtime = os.path.getmtime(full_p)
                        current_files[full_p] = mtime
                    except OSError:
                        pass

        # Check for new or updated files
        for path, mtime in current_files.items():
            if path not in self._known_files or self._known_files[path] < mtime:
                eval_res, _ = self.engine.scan_path(path)
                results.append((path, eval_res))
                if self.on_scan:
                    self.on_scan(path, eval_res)

        self._known_files = current_files
        return results
