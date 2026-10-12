"""
TorchScript, TorchDynamo, and TorchInductor Static Security Rules.
Defines security heuristics and denylists for TorchScript intermediate representation (IR)
and PyTorch 2.0 compiled graph artifacts.
"""

from typing import Dict, Set
from scanner.rules.dangerous_symbols import RiskLevel, SymbolRule

# Known dangerous IR primitives in TorchScript / TorchDynamo graphs
DANGEROUS_TORCHSCRIPT_OPS: Dict[str, SymbolRule] = {
    "prim::PythonOp": SymbolRule(
        module="torch.jit",
        name="prim::PythonOp",
        severity=RiskLevel.CRITICAL,
        category="python_fallback_execution",
        description="TorchScript node invokes raw Python interpreter fallback, allowing arbitrary host code execution.",
    ),
    "prim::CallFunction": SymbolRule(
        module="torch.jit",
        name="prim::CallFunction",
        severity=RiskLevel.HIGH,
        category="dynamic_dispatch",
        description="Dynamic function invocation in TorchScript graph bypassing static type and safety validation.",
    ),
    "prim::Print": SymbolRule(
        module="torch.jit",
        name="prim::Print",
        severity=RiskLevel.MEDIUM,
        category="side_channel",
        description="Graph print primitive potentially leaking internal tensor memory or serving as probe payload.",
    ),
    "prim::Enter": SymbolRule(
        module="torch.jit",
        name="prim::Enter",
        severity=RiskLevel.LOW,
        category="context_manager",
        description="Context manager entry in serialized graph.",
    ),
}

# Standard safe aten:: operators allowlist
SAFE_ATEN_PREFIXES: Set[str] = {
    "aten::add",
    "aten::sub",
    "aten::mul",
    "aten::div",
    "aten::matmul",
    "aten::mm",
    "aten::bmm",
    "aten::conv2d",
    "aten::relu",
    "aten::gelu",
    "aten::linear",
    "aten::batch_norm",
    "aten::layer_norm",
    "aten::softmax",
    "aten::view",
    "aten::reshape",
    "aten::transpose",
    "aten::permute",
}
