"""
Batch Scan Checkpoint and Incremental State Manager.
Maintains scan checkpoints on disk to allow resuming interrupted batch scans
and skipping unmodified model files based on mtime and size.
"""

import json
import os
from typing import Dict, Optional, Set


class ScanCheckpointManager:
    """Manages incremental scan state and resumption."""

    def __init__(self, checkpoint_path: str = ".mlsecops_checkpoint.json"):
        self.checkpoint_path = checkpoint_path
        self._state: Dict[str, Dict[str, float]] = self._load()

    def _load(self) -> Dict[str, Dict[str, float]]:
        if os.path.exists(self.checkpoint_path):
            try:
                with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save(self) -> None:
        try:
            with open(self.checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
        except Exception:
            pass

    def is_file_scanned(self, file_path: str) -> bool:
        """Checks if file was previously scanned and has not changed."""
        if not os.path.exists(file_path):
            return False
        stat = os.stat(file_path)
        record = self._state.get(file_path)
        if not record:
            return False
        return record.get("mtime") == stat.st_mtime and record.get("size") == stat.st_size

    def mark_scanned(self, file_path: str) -> None:
        if os.path.exists(file_path):
            stat = os.stat(file_path)
            self._state[file_path] = {
                "mtime": stat.st_mtime,
                "size": stat.st_size,
            }
