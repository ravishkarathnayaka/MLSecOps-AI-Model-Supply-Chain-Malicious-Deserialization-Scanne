"""
Unit tests validating CLI model directory watch daemon and incremental polling.
"""

import os
import shutil
import tempfile
import unittest

from cli.watch_daemon import ModelDirectoryWatcher


class TestModelDirectoryWatcher(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.events = []

        def callback(path, result):
            self.events.append((path, result.passed))

        self.watcher = ModelDirectoryWatcher(self.temp_dir, on_scan_callback=callback)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_new_model_file(self):
        # Initial poll: empty
        initial = self.watcher.poll_once()
        self.assertEqual(len(initial), 0)

        # Create dummy file with safetensors header
        safe_path = os.path.join(self.temp_dir, "model.safetensors")
        with open(safe_path, "wb") as f:
            f.write(b"\x02\x00\x00\x00\x00\x00\x00\x00{}")

        # Second poll: detects new file
        second = self.watcher.poll_once()
        self.assertEqual(len(second), 1)
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0][0], safe_path)

        # Third poll without changes: zero new scans
        third = self.watcher.poll_once()
        self.assertEqual(len(third), 0)


if __name__ == "__main__":
    unittest.main()
