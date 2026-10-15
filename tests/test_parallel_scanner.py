"""
Unit tests validating multi-threaded parallel model scanning worker pool.
"""

import os
import shutil
import tempfile
import unittest

from cli.parallel_scanner import ParallelModelScanner


class TestParallelModelScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = ParallelModelScanner(max_workers=2)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_multiple_files_parallel(self):
        # Create 3 synthetic model files
        paths = []
        for i in range(3):
            p = os.path.join(self.temp_dir, f"model_{i}.safetensors")
            with open(p, "wb") as f:
                f.write(b"\x02\x00\x00\x00\x00\x00\x00\x00{}")
            paths.append(p)

        eval_result, scanned = self.scanner.scan_files(paths)
        self.assertEqual(len(scanned), 3)
        self.assertTrue(eval_result.passed)


if __name__ == "__main__":
    unittest.main()
