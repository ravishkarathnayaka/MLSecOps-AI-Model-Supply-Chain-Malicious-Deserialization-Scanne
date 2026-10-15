"""
Security rules identifying low-level GPU kernel memory manipulation and CUDA driver escape vectors
during model deserialization and weight loading.
"""

from typing import Dict, Tuple
from scanner.rules.dangerous_symbols import RiskLevel, SymbolRule


GPU_MEMORY_RULES: Dict[Tuple[str, str], SymbolRule] = {
    ("ctypes", "memmove"): SymbolRule(
        module="ctypes",
        name="memmove",
        severity=RiskLevel.CRITICAL,
        category="gpu_memory_manipulation",
        description="Direct memory copy bypassing Python runtime bounds; risks memory corruption and container escape.",
    ),
    ("ctypes", "cast"): SymbolRule(
        module="ctypes",
        name="cast",
        severity=RiskLevel.HIGH,
        category="gpu_memory_manipulation",
        description="Arbitrary memory pointer cast enabling raw hardware address dereferencing.",
    ),
    ("torch.cuda", "csrc"): SymbolRule(
        module="torch.cuda",
        name="csrc",
        severity=RiskLevel.HIGH,
        category="gpu_memory_manipulation",
        description="Internal PyTorch CUDA C++ extension bindings; untrusted invocation can corrupt GPU context.",
    ),
    ("torch.cuda", "set_device"): SymbolRule(
        module="torch.cuda",
        name="set_device",
        severity=RiskLevel.MEDIUM,
        category="gpu_resource_hijacking",
        description="Dynamic GPU device re-allocation during model unpickling.",
    ),
    ("cupy.cuda.runtime", "memcpy"): SymbolRule(
        module="cupy.cuda.runtime",
        name="memcpy",
        severity=RiskLevel.CRITICAL,
        category="gpu_memory_manipulation",
        description="Direct CuPy CUDA memory copy operation.",
    ),
}


def lookup_gpu_memory_rule(module: str, name: str) -> SymbolRule | None:
    return GPU_MEMORY_RULES.get((module, name))
