"""
Automated Performance and Latency Benchmarking Suite.
Measures static opcode traversal rate (ops/sec), file throughput (MB/sec),
and multi-threaded parallel scanning efficiency.
"""

import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.analyzers.pickle_inspector import PickleInspector
from scanner.analyzers.safetensors_checker import SafetensorsChecker
from scanner.core.engine import ModelScanEngine
from scanner.core.parallel_scanner import ParallelModelScanner


def benchmark_pickle_inspector(iterations: int = 500) -> float:
    """Measures pickle opcode disassembly latency."""
    sample_file = os.path.join("test_models", "safe_model.pkl")
    if not os.path.exists(sample_file):
        return 0.0

    inspector = PickleInspector()
    t0 = time.perf_counter()
    for _ in range(iterations):
        inspector.inspect_file(sample_file)
    elapsed = time.perf_counter() - t0
    ops_per_sec = iterations / elapsed
    return round(ops_per_sec, 2)


def benchmark_safetensors_checker(iterations: int = 500) -> float:
    """Measures Safetensors zero-copy header validation latency."""
    sample_file = os.path.join("test_models", "safe_model.safetensors")
    if not os.path.exists(sample_file):
        return 0.0

    checker = SafetensorsChecker()
    t0 = time.perf_counter()
    for _ in range(iterations):
        checker.check_file(sample_file)
    elapsed = time.perf_counter() - t0
    checks_per_sec = iterations / elapsed
    return round(checks_per_sec, 2)


def run_benchmarks() -> None:
    print("=" * 60)
    print("MLSecOps Scanner Performance Benchmarks")
    print("=" * 60)

    pickle_rate = benchmark_pickle_inspector()
    print(f"[*] Pickle Inspector Throughput : {pickle_rate:,} files/sec")

    safetensors_rate = benchmark_safetensors_checker()
    print(f"[*] Safetensors Validator Rate   : {safetensors_rate:,} files/sec")

    # Parallel directory benchmark
    parallel_scanner = ParallelModelScanner(max_workers=4)
    t0 = time.perf_counter()
    eval_res, scanned, latencies = parallel_scanner.scan_directory_parallel("test_models")
    elapsed = time.perf_counter() - t0
    print(f"[*] Parallel Scan of {len(scanned)} models : {elapsed * 1000:.2f} ms")
    print("=" * 60)


if __name__ == "__main__":
    run_benchmarks()
