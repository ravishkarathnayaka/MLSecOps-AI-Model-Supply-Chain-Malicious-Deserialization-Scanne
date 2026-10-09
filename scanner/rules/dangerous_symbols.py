"""
Comprehensive denylist and safe allowlist of symbols and modules for ML model deserialization scanning.
Categorizes threat vectors into Code Execution, Process Spawning, File System Manipulation,
Network Exfiltration, and Dynamic Reflection.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Set, Tuple


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class SymbolRule:
    module: str
    name: str
    severity: RiskLevel
    category: str
    description: str


# Explicit denylist of dangerous callables (module, name) -> SymbolRule
DANGEROUS_CALLABLES: Dict[Tuple[str, str], SymbolRule] = {
    # Arbitrary Code Execution / Eval
    ("builtins", "eval"): SymbolRule(
        module="builtins",
        name="eval",
        severity=RiskLevel.CRITICAL,
        category="arbitrary_code_execution",
        description="Dynamic string evaluation enabling arbitrary Python code execution.",
    ),
    ("__builtin__", "eval"): SymbolRule(
        module="__builtin__",
        name="eval",
        severity=RiskLevel.CRITICAL,
        category="arbitrary_code_execution",
        description="Python 2 legacy dynamic string evaluation enabling arbitrary code execution.",
    ),
    ("builtins", "exec"): SymbolRule(
        module="builtins",
        name="exec",
        severity=RiskLevel.CRITICAL,
        category="arbitrary_code_execution",
        description="Dynamic statement execution enabling arbitrary Python code execution.",
    ),
    ("__builtin__", "exec"): SymbolRule(
        module="__builtin__",
        name="exec",
        severity=RiskLevel.CRITICAL,
        category="arbitrary_code_execution",
        description="Python 2 legacy statement execution enabling arbitrary code execution.",
    ),
    ("builtins", "compile"): SymbolRule(
        module="builtins",
        name="compile",
        severity=RiskLevel.CRITICAL,
        category="arbitrary_code_execution",
        description="Compiles source code into executable AST/code objects.",
    ),
    ("builtins", "__import__"): SymbolRule(
        module="builtins",
        name="__import__",
        severity=RiskLevel.CRITICAL,
        category="arbitrary_code_execution",
        description="Dynamic module importer used to bypass static imports.",
    ),
    ("importlib", "import_module"): SymbolRule(
        module="importlib",
        name="import_module",
        severity=RiskLevel.CRITICAL,
        category="arbitrary_code_execution",
        description="Dynamic runtime module loading often used in sandbox escapes.",
    ),

    # Process Spawning / OS Command Execution
    ("os", "system"): SymbolRule(
        module="os",
        name="system",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Executes arbitrary shell commands in a subshell.",
    ),
    ("posix", "system"): SymbolRule(
        module="posix",
        name="system",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="POSIX-level system shell execution.",
    ),
    ("nt", "system"): SymbolRule(
        module="nt",
        name="system",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Windows NT system shell execution.",
    ),
    ("os", "popen"): SymbolRule(
        module="os",
        name="popen",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Opens a pipe to or from a shell command.",
    ),
    ("os", "spawnl"): SymbolRule(
        module="os",
        name="spawnl",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Spawns a new OS process.",
    ),
    ("os", "spawnle"): SymbolRule(
        module="os",
        name="spawnle",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Spawns a new OS process with custom environment.",
    ),
    ("os", "spawnlp"): SymbolRule(
        module="os",
        name="spawnlp",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Spawns a new OS process resolving PATH.",
    ),
    ("os", "spawnv"): SymbolRule(
        module="os",
        name="spawnv",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Spawns a new OS process with vector arguments.",
    ),
    ("os", "spawnve"): SymbolRule(
        module="os",
        name="spawnve",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Spawns a new OS process with vector arguments and environment.",
    ),
    ("os", "execl"): SymbolRule(
        module="os",
        name="execl",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Replaces current process with new process image.",
    ),
    ("os", "execle"): SymbolRule(
        module="os",
        name="execle",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Replaces current process with new process image and environment.",
    ),
    ("os", "execv"): SymbolRule(
        module="os",
        name="execv",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Replaces current process with new process vector.",
    ),
    ("os", "execve"): SymbolRule(
        module="os",
        name="execve",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Replaces current process with new process vector and environment.",
    ),
    ("subprocess", "Popen"): SymbolRule(
        module="subprocess",
        name="Popen",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Spawns arbitrary background or synchronous subprocesses.",
    ),
    ("subprocess", "call"): SymbolRule(
        module="subprocess",
        name="call",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Runs command in subprocess and returns exit status.",
    ),
    ("subprocess", "check_call"): SymbolRule(
        module="subprocess",
        name="check_call",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Runs command in subprocess checking exit code.",
    ),
    ("subprocess", "check_output"): SymbolRule(
        module="subprocess",
        name="check_output",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Executes command and captures stdout output.",
    ),
    ("subprocess", "run"): SymbolRule(
        module="subprocess",
        name="run",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Standard subprocess execution interface.",
    ),
    ("pty", "spawn"): SymbolRule(
        module="pty",
        name="spawn",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Spawns a pseudo-terminal (frequent interactive reverse shell primitive).",
    ),
    ("commands", "getoutput"): SymbolRule(
        module="commands",
        name="getoutput",
        severity=RiskLevel.CRITICAL,
        category="process_spawning",
        description="Executes shell command (legacy).",
    ),

    # File System Tampering / Destruction
    ("builtins", "open"): SymbolRule(
        module="builtins",
        name="open",
        severity=RiskLevel.HIGH,
        category="filesystem_tampering",
        description="Opens arbitrary local file handles for read, write, or append.",
    ),
    ("io", "FileIO"): SymbolRule(
        module="io",
        name="FileIO",
        severity=RiskLevel.HIGH,
        category="filesystem_tampering",
        description="Low-level file stream opener bypassing builtins.",
    ),
    ("shutil", "rmtree"): SymbolRule(
        module="shutil",
        name="rmtree",
        severity=RiskLevel.CRITICAL,
        category="filesystem_destruction",
        description="Recursively deletes entire file system directory trees.",
    ),
    ("os", "remove"): SymbolRule(
        module="os",
        name="remove",
        severity=RiskLevel.HIGH,
        category="filesystem_tampering",
        description="Deletes a file path from disk.",
    ),
    ("os", "unlink"): SymbolRule(
        module="os",
        name="unlink",
        severity=RiskLevel.HIGH,
        category="filesystem_tampering",
        description="Unlinks a file from disk.",
    ),
    ("pathlib", "Path"): SymbolRule(
        module="pathlib",
        name="Path",
        severity=RiskLevel.MEDIUM,
        category="filesystem_tampering",
        description="Path object construction (suspicious if invoked with write/unlink).",
    ),

    # Network Exfiltration / Sockets
    ("socket", "socket"): SymbolRule(
        module="socket",
        name="socket",
        severity=RiskLevel.CRITICAL,
        category="network_exfiltration",
        description="Creates raw network sockets for outbound exfiltration or reverse shells.",
    ),
    ("socket", "create_connection"): SymbolRule(
        module="socket",
        name="create_connection",
        severity=RiskLevel.CRITICAL,
        category="network_exfiltration",
        description="Establishes outbound TCP socket connections.",
    ),
    ("urllib.request", "urlopen"): SymbolRule(
        module="urllib.request",
        name="urlopen",
        severity=RiskLevel.HIGH,
        category="network_exfiltration",
        description="Performs outbound HTTP/HTTPS requests to download secondary payloads.",
    ),
    ("urllib.request", "urlretrieve"): SymbolRule(
        module="urllib.request",
        name="urlretrieve",
        severity=RiskLevel.HIGH,
        category="network_exfiltration",
        description="Downloads remote files directly onto local disk.",
    ),
    ("requests", "get"): SymbolRule(
        module="requests",
        name="get",
        severity=RiskLevel.HIGH,
        category="network_exfiltration",
        description="Outbound HTTP GET request.",
    ),
    ("requests", "post"): SymbolRule(
        module="requests",
        name="post",
        severity=RiskLevel.HIGH,
        category="network_exfiltration",
        description="Outbound HTTP POST request for data exfiltration.",
    ),
    ("http.client", "HTTPConnection"): SymbolRule(
        module="http.client",
        name="HTTPConnection",
        severity=RiskLevel.HIGH,
        category="network_exfiltration",
        description="Low-level HTTP connection client.",
    ),

    # Reflection / Attribute Injection
    ("builtins", "getattr"): SymbolRule(
        module="builtins",
        name="getattr",
        severity=RiskLevel.HIGH,
        category="reflection",
        description="Dynamic attribute resolution used to circumvent symbol denylists.",
    ),
    ("builtins", "setattr"): SymbolRule(
        module="builtins",
        name="setattr",
        severity=RiskLevel.HIGH,
        category="reflection",
        description="Mutates object attributes dynamically at runtime.",
    ),

    # Benign Synthetic Test Payload Callables
    ("builtins", "print"): SymbolRule(
        module="builtins",
        name="print",
        severity=RiskLevel.HIGH,
        category="synthetic_probe",
        description="Standard print function. Safe payload callback used in synthetic benign tests.",
    ),
}

# Modules that should NEVER appear in benign machine learning weight pickles
DANGEROUS_MODULES: Dict[str, Tuple[RiskLevel, str]] = {
    "os": (RiskLevel.CRITICAL, "Operating system interface module"),
    "posix": (RiskLevel.CRITICAL, "POSIX low-level OS primitives"),
    "nt": (RiskLevel.CRITICAL, "Windows NT low-level OS primitives"),
    "subprocess": (RiskLevel.CRITICAL, "Process creation and shell execution module"),
    "pty": (RiskLevel.CRITICAL, "Pseudo-terminal control module"),
    "socket": (RiskLevel.CRITICAL, "Low-level networking and socket interface"),
    "commands": (RiskLevel.CRITICAL, "Legacy shell execution module"),
    "shutil": (RiskLevel.HIGH, "High-level file operations and directory removal"),
    "urllib": (RiskLevel.HIGH, "URL handling and outbound network fetching"),
    "requests": (RiskLevel.HIGH, "HTTP client library"),
    "http": (RiskLevel.HIGH, "HTTP protocol client module"),
    "ftplib": (RiskLevel.HIGH, "FTP client module"),
    "webbrowser": (RiskLevel.HIGH, "System browser launcher"),
    "importlib": (RiskLevel.HIGH, "Dynamic module loading machinery"),
    "inspect": (RiskLevel.MEDIUM, "Runtime code reflection and introspection"),
    "ctypes": (RiskLevel.CRITICAL, "Foreign function library allowing direct C memory access"),
    "code": (RiskLevel.HIGH, "Interactive interpreter and compilation machinery"),
}

# Allowlisted standard machine learning weights / tensor primitives
KNOWN_SAFE_GLOBALS: Set[Tuple[str, str]] = {
    # PyTorch internals
    ("torch._utils", "_rebuild_tensor"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("torch._utils", "_rebuild_parameter"),
    ("torch._utils", "_rebuild_sparse_tensor"),
    ("torch", "FloatStorage"),
    ("torch", "HalfStorage"),
    ("torch", "DoubleStorage"),
    ("torch", "BFloat16Storage"),
    ("torch", "IntStorage"),
    ("torch", "LongStorage"),
    ("torch", "ShortStorage"),
    ("torch", "ByteStorage"),
    ("torch", "CharStorage"),
    ("torch", "BoolStorage"),
    ("torch", "storage"),
    ("torch", "Tensor"),
    ("torch", "device"),
    ("torch", "dtype"),
    ("torch", "Size"),

    # NumPy primitives
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("numpy._core.multiarray", "_reconstruct"),
    ("numpy._core.multiarray", "scalar"),
    ("numpy", "ndarray"),
    ("numpy", "dtype"),

    # Standard Python collections & encoding
    ("collections", "OrderedDict"),
    ("collections", "defaultdict"),
    ("_codecs", "encode"),
    ("copyreg", "_reconstructor"),
}


def lookup_symbol_rule(module: str, name: str) -> Optional[SymbolRule]:
    """
    Checks if a given module and symbol name match an explicit dangerous callable rule
    or belong to a dangerous module.
    """
    key = (module, name)
    if key in DANGEROUS_CALLABLES:
        return DANGEROUS_CALLABLES[key]

    # Check top-level package or exact module against dangerous module denylist
    top_module = module.split(".")[0]
    if module in DANGEROUS_MODULES:
        severity, desc = DANGEROUS_MODULES[module]
        return SymbolRule(
            module=module,
            name=name,
            severity=severity,
            category="dangerous_module_import",
            description=f"Import of symbol from forbidden module '{module}': {desc}.",
        )
    if top_module in DANGEROUS_MODULES:
        severity, desc = DANGEROUS_MODULES[top_module]
        return SymbolRule(
            module=module,
            name=name,
            severity=severity,
            category="dangerous_module_import",
            description=f"Import of symbol from forbidden package hierarchy '{top_module}': {desc}.",
        )

    return None


def is_allowlisted_global(module: str, name: str) -> bool:
    """Checks if a global is known safe for standard tensor deserialization."""
    if (module, name) in KNOWN_SAFE_GLOBALS:
        return True
    # Safe PyTorch modules (layers, activations, containers)
    if module.startswith("torch.nn.modules.") or module.startswith("torch.optim."):
        return True
    return False
