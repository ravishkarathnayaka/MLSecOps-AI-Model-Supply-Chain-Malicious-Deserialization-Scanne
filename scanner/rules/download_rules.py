"""
Rules detecting dynamic remote payload and weight downloader invocations during model deserialization.
Catches 2nd-stage payload staging, C2 downloads, and dynamic untrusted weight fetching.
"""

from typing import Dict, Tuple
from scanner.rules.dangerous_symbols import RiskLevel, SymbolRule


REMOTE_DOWNLOAD_CALLABLES: Dict[Tuple[str, str], SymbolRule] = {
    ("urllib.request", "urlopen"): SymbolRule(
        module="urllib.request",
        name="urlopen",
        severity=RiskLevel.CRITICAL,
        category="remote_payload_download",
        description="Standard library remote URL opening, commonly used to fetch secondary attack payloads.",
    ),
    ("urllib.request", "urlretrieve"): SymbolRule(
        module="urllib.request",
        name="urlretrieve",
        severity=RiskLevel.CRITICAL,
        category="remote_payload_download",
        description="Downloads a remote URL directly to disk during model loading.",
    ),
    ("urllib", "urlretrieve"): SymbolRule(
        module="urllib",
        name="urlretrieve",
        severity=RiskLevel.CRITICAL,
        category="remote_payload_download",
        description="Legacy urllib remote download to disk.",
    ),
    ("requests", "get"): SymbolRule(
        module="requests",
        name="get",
        severity=RiskLevel.HIGH,
        category="remote_payload_download",
        description="Dynamic HTTP GET request executed within model weights.",
    ),
    ("requests", "post"): SymbolRule(
        module="requests",
        name="post",
        severity=RiskLevel.HIGH,
        category="remote_payload_download",
        description="Dynamic HTTP POST request executed within model weights.",
    ),
    ("httpx", "get"): SymbolRule(
        module="httpx",
        name="get",
        severity=RiskLevel.HIGH,
        category="remote_payload_download",
        description="HTTPX dynamic client fetching remote content during deserialization.",
    ),
    ("wget", "download"): SymbolRule(
        module="wget",
        name="download",
        severity=RiskLevel.CRITICAL,
        category="remote_payload_download",
        description="Explicit wget download utility invoked inside model weights.",
    ),
    ("torch.hub", "download_url_to_file"): SymbolRule(
        module="torch.hub",
        name="download_url_to_file",
        severity=RiskLevel.HIGH,
        category="remote_payload_download",
        description="PyTorch hub utility downloading external weights from arbitrary URLs.",
    ),
}


def lookup_download_rule(module: str, name: str) -> SymbolRule | None:
    """Checks if a (module, name) pair matches a remote downloader rule."""
    return REMOTE_DOWNLOAD_CALLABLES.get((module, name))
