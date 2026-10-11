"""
Shannon Entropy and Steganographic Payload Detection Engine.
Calculates byte-level entropy distributions across model files and tensor buffers.
Detects encrypted shellcode, obfuscated loaders, and high-entropy anomalies embedded in model weights.
"""

import math
import os
from typing import Dict, List, Optional, Tuple

from scanner.rules.dangerous_symbols import RiskLevel
from scanner.rules.policy_engine import Finding

DEFAULT_CHUNK_SIZE = 4096
HIGH_ENTROPY_THRESHOLD = 7.92  # Bits per byte (Max theoretical is 8.0)


class EntropyAnalyzer:
    """
    Analyzes model binary entropy to detect hidden, encrypted, or packed steganographic payloads.
    """

    def __init__(self, high_threshold: float = HIGH_ENTROPY_THRESHOLD, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.high_threshold = high_threshold
        self.chunk_size = chunk_size

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """Computes Shannon entropy in bits per byte (0.0 to 8.0)."""
        if not data:
            return 0.0

        length = len(data)
        freq: Dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    def analyze_bytes(self, data: bytes, source_name: str = "buffer") -> List[Finding]:
        """Analyzes byte stream across sliding window chunks."""
        findings: List[Finding] = []
        if len(data) < self.chunk_size:
            overall = self.calculate_shannon_entropy(data)
            if overall >= self.high_threshold and len(data) > 1024:
                findings.append(
                    Finding(
                        rule_id="ENTROPY-ANOMALY-HIGH",
                        title=f"High Shannon Entropy Detected ({overall:.2f} bits/byte)",
                        severity=RiskLevel.MEDIUM,
                        category="steganography",
                        description=(
                            f"Byte buffer exhibits unusually high entropy ({overall:.2f}/8.0), "
                            "indicating potential encrypted shellcode, compressed blobs, or obfuscated payloads."
                        ),
                        location=source_name,
                        details={"entropy": overall, "size": len(data)},
                    )
                )
            return findings

        # Chunk-based scanning
        anomalous_chunks: List[Tuple[int, float]] = []
        for offset in range(0, len(data), self.chunk_size):
            chunk = data[offset : offset + self.chunk_size]
            if len(chunk) < 512:
                continue
            e = self.calculate_shannon_entropy(chunk)
            if e >= self.high_threshold:
                anomalous_chunks.append((offset, e))

        if anomalous_chunks:
            highest_chunk = max(anomalous_chunks, key=lambda x: x[1])
            findings.append(
                Finding(
                    rule_id="ENTROPY-ANOMALY-HIGH",
                    title=f"High-Entropy Region Detected ({highest_chunk[1]:.2f} bits/byte)",
                    severity=RiskLevel.MEDIUM,
                    category="steganography",
                    description=(
                        f"Detected {len(anomalous_chunks)} high-entropy chunk(s). "
                        f"Peak entropy at offset 0x{highest_chunk[0]:06X} ({highest_chunk[1]:.2f}/8.0 bits/byte) "
                        "suggests hidden encrypted or packed executable payload."
                    ),
                    location=f"{source_name} [Offset: 0x{highest_chunk[0]:06X}]",
                    details={
                        "peak_entropy": highest_chunk[1],
                        "peak_offset": highest_chunk[0],
                        "anomalous_chunk_count": len(anomalous_chunks),
                    },
                )
            )

        return findings

    def analyze_file(self, file_path: str) -> List[Finding]:
        if not os.path.exists(file_path):
            return []
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self.analyze_bytes(data, source_name=file_path)
        except Exception as e:
            return [
                Finding(
                    rule_id="ENTROPY-READ-ERROR",
                    title="Error Reading File for Entropy Analysis",
                    severity=RiskLevel.LOW,
                    category="io_error",
                    description=str(e),
                    location=file_path,
                )
            ]
