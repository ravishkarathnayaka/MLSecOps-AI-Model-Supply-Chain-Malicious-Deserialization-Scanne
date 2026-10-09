"""
Pickle Bytecode Static Disassembly Engine.
Analyzes raw pickle streams using pickletools.genops without executing untrusted weights.
Detects opcode injection (REDUCE, BUILD, INST, OBJ), dangerous global imports (GLOBAL, STACK_GLOBAL),
and maintains a simulated stack to reconstruct dangerous callable invocations.
"""

import io
import pickletools
from typing import Any, Dict, List, Optional, Set, Tuple

from scanner.rules.dangerous_symbols import (
    RiskLevel,
    is_allowlisted_global,
    lookup_symbol_rule,
)
from scanner.rules.policy_engine import Finding


class PickleStackItem:
    """Represents a tracked entity on the simulated opcode execution stack."""

    def __init__(self, kind: str, value: Any = None, pos: int = 0):
        self.kind = kind  # 'string', 'global', 'tuple', 'list', 'dict', 'mark', 'other'
        self.value = value
        self.pos = pos

    def __repr__(self) -> str:
        return f"StackItem({self.kind}, {self.value!r})"


class PickleInspector:
    """
    Statically inspects pickle bytecode streams without calling pickle.load().
    """

    def __init__(self, strict_mode: bool = False, custom_allowed: Optional[Set[Tuple[str, str]]] = None):
        self.strict_mode = strict_mode
        self.custom_allowed = custom_allowed or set()

    def inspect_bytes(self, data: bytes, source_name: str = "stream") -> List[Finding]:
        """Inspects raw byte data containing a pickle stream."""
        return self.inspect_stream(io.BytesIO(data), source_name=source_name)

    def inspect_file(self, file_path: str) -> List[Finding]:
        """Inspects a file containing raw pickle bytecode."""
        try:
            with open(file_path, "rb") as f:
                return self.inspect_stream(f, source_name=file_path)
        except Exception as e:
            return [
                Finding(
                    rule_id="PICKLE-FILE-READ-ERROR",
                    title="Failed to Read Pickle File",
                    severity=RiskLevel.HIGH,
                    category="io_error",
                    description=f"Error reading model file {file_path}: {str(e)}",
                    location=file_path,
                    details={"error": str(e)},
                )
            ]

    def inspect_stream(self, stream: io.BufferedIOBase, source_name: str = "stream") -> List[Finding]:
        findings: List[Finding] = []
        stack: List[PickleStackItem] = []
        memo: Dict[int, PickleStackItem] = {}
        detected_globals: List[Tuple[str, str, int]] = []

        try:
            ops = pickletools.genops(stream)
            for opcode, arg, pos in ops:
                op_name = opcode.name

                # --- 1. GLOBAL (Protocols 0-3) ---
                if op_name == "GLOBAL":
                    # arg format: "module name"
                    if arg and " " in arg:
                        module, name = arg.split(" ", 1)
                    else:
                        module, name = (arg or "unknown"), ""
                    detected_globals.append((module, name, pos))
                    g_item = PickleStackItem(kind="global", value=(module, name), pos=pos)
                    stack.append(g_item)
                    self._check_global(module, name, pos, source_name, findings)

                # --- 2. STACK_GLOBAL (Protocol 4+) ---
                elif op_name == "STACK_GLOBAL":
                    # Pops name then module from stack
                    name_val = "unknown"
                    module_val = "unknown"
                    if len(stack) >= 2:
                        name_item = stack.pop()
                        module_item = stack.pop()
                        name_val = str(name_item.value) if name_item.value is not None else "unknown"
                        module_val = str(module_item.value) if module_item.value is not None else "unknown"
                    elif len(stack) == 1:
                        name_item = stack.pop()
                        name_val = str(name_item.value) if name_item.value is not None else "unknown"

                    detected_globals.append((module_val, name_val, pos))
                    g_item = PickleStackItem(kind="global", value=(module_val, name_val), pos=pos)
                    stack.append(g_item)
                    self._check_global(module_val, name_val, pos, source_name, findings)

                # --- 3. Stack pushing string/constant opcodes ---
                elif op_name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINSTRING", "SHORT_BINSTRING", "STRING"):
                    stack.append(PickleStackItem(kind="string", value=str(arg), pos=pos))

                elif op_name in ("BININT", "BININT1", "BININT2", "INT", "LONG", "LONG1", "LONG4"):
                    stack.append(PickleStackItem(kind="int", value=arg, pos=pos))

                elif op_name in ("NONE", "TRUE", "FALSE"):
                    stack.append(PickleStackItem(kind="const", value=arg, pos=pos))

                elif op_name == "MARK":
                    stack.append(PickleStackItem(kind="mark", value=None, pos=pos))

                # --- 4. Container constructors ---
                elif op_name in ("TUPLE", "TUPLE1", "TUPLE2", "TUPLE3"):
                    num = {"TUPLE1": 1, "TUPLE2": 2, "TUPLE3": 3}.get(op_name)
                    items: List[Any] = []
                    if num:
                        for _ in range(min(num, len(stack))):
                            items.insert(0, stack.pop())
                    else:
                        # POP until MARK
                        while stack:
                            top = stack.pop()
                            if top.kind == "mark":
                                break
                            items.insert(0, top)
                    stack.append(PickleStackItem(kind="tuple", value=items, pos=pos))

                elif op_name == "EMPTY_TUPLE":
                    stack.append(PickleStackItem(kind="tuple", value=[], pos=pos))

                elif op_name in ("LIST", "EMPTY_LIST", "APPEND", "APPENDS"):
                    if op_name == "EMPTY_LIST":
                        stack.append(PickleStackItem(kind="list", value=[], pos=pos))

                elif op_name in ("DICT", "EMPTY_DICT", "SETITEM", "SETITEMS"):
                    if op_name == "EMPTY_DICT":
                        stack.append(PickleStackItem(kind="dict", value={}, pos=pos))

                # --- 5. Dangerous Invocations: REDUCE, BUILD, INST, OBJ, NEWOBJ ---
                elif op_name == "REDUCE":
                    # REDUCE pops args tuple, then callable: callable(*args)
                    callable_target: Optional[PickleStackItem] = None
                    args_target: Optional[PickleStackItem] = None

                    if len(stack) >= 2:
                        args_target = stack.pop()
                        callable_target = stack.pop()
                    elif len(stack) == 1:
                        callable_target = stack.pop()

                    self._check_reduce(callable_target, args_target, pos, source_name, findings)
                    # Push result placeholder
                    stack.append(PickleStackItem(kind="reduced_result", value=None, pos=pos))

                elif op_name == "BUILD":
                    # BUILD pops state and applies it to instance.__setstate__(state)
                    state = stack.pop() if stack else None
                    inst = stack[-1] if stack else None
                    self._check_build(inst, state, pos, source_name, findings)

                elif op_name == "INST":
                    # Instantiates module/class with arguments from stack
                    # arg format: "module name"
                    if arg and " " in arg:
                        module, name = arg.split(" ", 1)
                    else:
                        module, name = (arg or "unknown"), ""
                    self._check_inst(module, name, pos, source_name, findings)
                    stack.append(PickleStackItem(kind="instance", value=(module, name), pos=pos))

                elif op_name == "OBJ":
                    # Builds an object finding class above MARK
                    stack.append(PickleStackItem(kind="obj", value=None, pos=pos))

                elif op_name in ("PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE"):
                    if stack:
                        idx = arg if arg is not None else len(memo)
                        memo[idx] = stack[-1]

                elif op_name in ("GET", "BINGET", "LONG_BINGET"):
                    if arg in memo:
                        stack.append(memo[arg])

                elif op_name == "STOP":
                    break

        except Exception as ex:
            # Traversal error or malformed stream
            findings.append(
                Finding(
                    rule_id="PICKLE-MALFORMED-STREAM",
                    title="Malformed or Truncated Pickle Bytecode",
                    severity=RiskLevel.HIGH,
                    category="syntax_anomaly",
                    description=f"Pickle stream parsing encountered syntax/structure error: {str(ex)}",
                    location=f"{source_name}:offset",
                    details={"exception": str(ex), "type": type(ex).__name__},
                )
            )

        return findings

    def _check_global(
        self,
        module: str,
        name: str,
        pos: int,
        source_name: str,
        findings: List[Finding],
    ) -> None:
        """Inspects an imported global against safety denylists and allowlists."""
        rule = lookup_symbol_rule(module, name)
        location = f"{source_name} [Bytecode Offset: 0x{pos:04X}]"

        if rule:
            findings.append(
                Finding(
                    rule_id=f"DANGEROUS-GLOBAL-{rule.severity.value}",
                    title=f"Dangerous Global Reference: {module}.{name}",
                    severity=rule.severity,
                    category=rule.category,
                    description=rule.description,
                    location=location,
                    details={
                        "module": module,
                        "symbol": name,
                        "offset": pos,
                        "hex_offset": hex(pos),
                        "opcode": "GLOBAL",
                    },
                )
            )
            return

        # Check if known safe
        if (module, name) in self.custom_allowed or is_allowlisted_global(module, name):
            return

        # If strict mode is enabled, unknown globals are flagged
        if self.strict_mode:
            findings.append(
                Finding(
                    rule_id="UNKNOWN-GLOBAL-STRICT",
                    title=f"Unrecognized Global Symbol: {module}.{name}",
                    severity=RiskLevel.MEDIUM,
                    category="strict_policy_violation",
                    description=(
                        f"Strict verification mode flagged unverified global reference '{module}.{name}'. "
                        "Weight files should only reference recognized tensor/array builders."
                    ),
                    location=location,
                    details={"module": module, "symbol": name, "offset": pos},
                )
            )

    def _check_reduce(
        self,
        callable_target: Optional[PickleStackItem],
        args_target: Optional[PickleStackItem],
        pos: int,
        source_name: str,
        findings: List[Finding],
    ) -> None:
        """Evaluates a REDUCE opcode invocation against dangerous callables."""
        location = f"{source_name} [Bytecode Offset: 0x{pos:04X}]"

        if callable_target and callable_target.kind == "global":
            module, name = callable_target.value
            rule = lookup_symbol_rule(module, name)
            if rule:
                args_repr = repr(args_target.value) if args_target else "()"
                findings.append(
                    Finding(
                        rule_id="ARBITRARY-CODE-EXECUTION-REDUCE",
                        title=f"Malicious REDUCE Opcode Injected: {module}.{name}",
                        severity=RiskLevel.CRITICAL if rule.severity != RiskLevel.INFO else RiskLevel.MEDIUM,
                        category="code_execution",
                        description=(
                            f"REDUCE opcode executes callable '{module}.{name}' during deserialization. "
                            f"Argument payload signature: {args_repr}. "
                            f"This facilitates immediate arbitrary code execution upon model loading."
                        ),
                        location=location,
                        details={
                            "callable_module": module,
                            "callable_name": name,
                            "offset": pos,
                            "hex_offset": hex(pos),
                            "opcode": "REDUCE",
                            "rule_category": rule.category,
                        },
                    )
                )

    def _check_build(
        self,
        instance: Optional[PickleStackItem],
        state: Optional[PickleStackItem],
        pos: int,
        source_name: str,
        findings: List[Finding],
    ) -> None:
        """Inspects BUILD opcode states for suspicious attributes."""
        # Check if state contains dangerous callable injections or overrides
        if state and isinstance(state.value, dict):
            for k, v in state.value.items():
                if str(k) in ("__reduce__", "__reduce_ex__"):
                    findings.append(
                        Finding(
                            rule_id="SUSPICIOUS-BUILD-STATE",
                            title="Tampered Object State in BUILD Opcode",
                            severity=RiskLevel.HIGH,
                            category="state_tampering",
                            description=f"State dictionary overrides magic method '{k}'.",
                            location=f"{source_name} [Bytecode Offset: 0x{pos:04X}]",
                            details={"key": str(k), "offset": pos},
                        )
                    )

    def _check_inst(
        self,
        module: str,
        name: str,
        pos: int,
        source_name: str,
        findings: List[Finding],
    ) -> None:
        """Inspects legacy INST opcode."""
        rule = lookup_symbol_rule(module, name)
        if rule:
            findings.append(
                Finding(
                    rule_id="DANGEROUS-INST-OPCODE",
                    title=f"Dangerous INST Opcode: {module}.{name}",
                    severity=rule.severity,
                    category="code_execution",
                    description=f"INST opcode creates instance of '{module}.{name}': {rule.description}",
                    location=f"{source_name} [Bytecode Offset: 0x{pos:04X}]",
                    details={"module": module, "name": name, "offset": pos},
                )
            )
