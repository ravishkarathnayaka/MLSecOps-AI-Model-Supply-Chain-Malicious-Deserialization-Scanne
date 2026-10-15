"""
Unit tests validating Kubernetes liveness and readiness probe evaluations.
"""

import unittest
from admission_gate.health_probes import HealthProbeManager


class TestHealthProbes(unittest.TestCase):
    def test_livez_always_healthy(self):
        manager = HealthProbeManager()
        status = manager.check_livez()
        self.assertTrue(status.healthy)
        self.assertEqual(status.status_code, 200)
        self.assertIn("uptime_seconds", status.details)

    def test_readyz_healthy_without_redis(self):
        manager = HealthProbeManager()
        status = manager.check_readyz()
        self.assertTrue(status.healthy)
        self.assertEqual(status.status_code, 200)

    def test_readyz_redis_failure(self):
        def failing_redis():
            return False

        manager = HealthProbeManager(check_redis_callable=failing_redis)
        status = manager.check_readyz()
        self.assertFalse(status.healthy)
        self.assertEqual(status.status_code, 503)
        self.assertEqual(status.details.get("redis"), "disconnected")

    def test_ready_override_unready(self):
        manager = HealthProbeManager()
        manager.ready_override = False
        status = manager.check_readyz()
        self.assertFalse(status.healthy)
        self.assertEqual(status.status_code, 503)


if __name__ == "__main__":
    unittest.main()
