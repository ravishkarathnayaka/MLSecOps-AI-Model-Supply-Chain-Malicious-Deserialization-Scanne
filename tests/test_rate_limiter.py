"""
Unit tests validating admission rate-limiting middleware and token bucket algorithm.
"""

import time
import unittest
from admission_gate.rate_limiter import AdmissionRateLimiter, TokenBucket


class TestAdmissionRateLimiter(unittest.TestCase):
    def test_token_bucket_consume_and_refill(self):
        bucket = TokenBucket(capacity=2, refill_rate=10.0)
        self.assertTrue(bucket.consume(1))
        self.assertTrue(bucket.consume(1))
        # Exhausted
        self.assertFalse(bucket.consume(1))

        # Sleep brief moment to allow refill
        time.sleep(0.15)
        self.assertTrue(bucket.consume(1))

    def test_rate_limiter_per_client(self):
        limiter = AdmissionRateLimiter(default_capacity=2, default_refill_rate=1.0)
        # Client A consumes 2 tokens
        allowed_a1, _ = limiter.check_limit("192.168.1.10", 1)
        allowed_a2, _ = limiter.check_limit("192.168.1.10", 1)
        allowed_a3, retry_after = limiter.check_limit("192.168.1.10", 1)

        self.assertTrue(allowed_a1)
        self.assertTrue(allowed_a2)
        self.assertFalse(allowed_a3)
        self.assertGreater(retry_after, 0)

        # Client B has separate bucket and should succeed
        allowed_b, _ = limiter.check_limit("10.0.0.5", 1)
        self.assertTrue(allowed_b)


if __name__ == "__main__":
    unittest.main()
