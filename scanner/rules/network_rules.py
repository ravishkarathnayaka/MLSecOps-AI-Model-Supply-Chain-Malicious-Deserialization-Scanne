"""
Network Exfiltration and Socket Protocol Rules.
Flags advanced covert exfiltration primitives embedded within model weights:
DNS tunneling, raw ICMP sockets, gRPC channels, and asynchronous HTTP clients.
"""

from typing import Dict, Tuple
from scanner.rules.dangerous_symbols import RiskLevel, SymbolRule

NETWORK_EXFILTRATION_RULES: Dict[Tuple[str, str], SymbolRule] = {
    ("socket", "gethostbyname"): SymbolRule(
        module="socket",
        name="gethostbyname",
        severity=RiskLevel.HIGH,
        category="dns_exfiltration",
        description="DNS resolution primitive commonly exploited for DNS tunneling and out-of-band exfiltration.",
    ),
    ("socket", "getaddrinfo"): SymbolRule(
        module="socket",
        name="getaddrinfo",
        severity=RiskLevel.HIGH,
        category="dns_exfiltration",
        description="Address resolution function used in covert network channels.",
    ),
    ("grpc", "insecure_channel"): SymbolRule(
        module="grpc",
        name="insecure_channel",
        severity=RiskLevel.HIGH,
        category="rpc_exfiltration",
        description="Creates unauthenticated gRPC communication channels to external endpoints.",
    ),
    ("httpx", "Client"): SymbolRule(
        module="httpx",
        name="Client",
        severity=RiskLevel.HIGH,
        category="http_exfiltration",
        description="Modern HTTP client capable of outbound weight or environment data transmission.",
    ),
    ("aiohttp", "ClientSession"): SymbolRule(
        module="aiohttp",
        name="ClientSession",
        severity=RiskLevel.HIGH,
        category="http_exfiltration",
        description="Asynchronous HTTP client session commonly used in modern background exfiltration bots.",
    ),
}
