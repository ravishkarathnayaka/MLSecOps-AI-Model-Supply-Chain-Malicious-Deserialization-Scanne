"""
Token Bucket Rate Limiting Middleware for MLSecOps Admission Controller Webhook.
Protects model admission gates from volumetric Denial of Service (DoS) and API abuse.
"""

from collections import defaultdict
import threading
import time
from typing import Dict, Optional, Tuple


class TokenBucket:
    """Thread-safe Token Bucket rate limiter."""

    def __init__(self, capacity: int = 60, refill_rate: float = 1.0):
        self.capacity = float(capacity)
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = float(capacity)
        self.last_update = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now

            # Refill tokens
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class AdmissionRateLimiter:
    """Tracks rate limiting token buckets per client key (IP or namespace)."""

    def __init__(self, default_capacity: int = 60, default_refill_rate: float = 1.0):
        self.default_capacity = default_capacity
        self.default_refill_rate = default_refill_rate
        self.buckets: Dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self.default_capacity, self.default_refill_rate)
        )
        self.lock = threading.Lock()

    def check_limit(self, client_key: str, tokens: int = 1) -> Tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        with self.lock:
            bucket = self.buckets[client_key]
        allowed = bucket.consume(tokens)
        if allowed:
            return True, 0
        return False, int(max(1, 1.0 / self.default_refill_rate))
