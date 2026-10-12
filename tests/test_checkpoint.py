"""
Unit tests for ScanCheckpointManager.
Validates incremental state persistence, resumption logic, and mtime invalidation.
"""

from cli.checkpoint import ScanCheckpointManager


def test_checkpoint_unscanned_file(tmp_path):
    ckpt_file = tmp_path / "checkpoint.json"
    mgr = ScanCheckpointManager(str(ckpt_file))
    test_target = tmp_path / "model.pt"
    test_target.write_bytes(b"data")

    assert mgr.is_file_scanned(str(test_target)) is False


def test_checkpoint_mark_and_resume(tmp_path):
    ckpt_file = tmp_path / "checkpoint.json"
    mgr = ScanCheckpointManager(str(ckpt_file))
    test_target = tmp_path / "model.pt"
    test_target.write_bytes(b"data")

    mgr.mark_scanned(str(test_target))
    mgr.save()
    assert mgr.is_file_scanned(str(test_target)) is True

    # New manager instance loads saved state
    mgr2 = ScanCheckpointManager(str(ckpt_file))
    assert mgr2.is_file_scanned(str(test_target)) is True

    # Mutate file content -> cache invalidated
    test_target.write_bytes(b"modified new weights data")
    assert mgr2.is_file_scanned(str(test_target)) is False
