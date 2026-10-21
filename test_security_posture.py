import unittest

from security_posture import evaluate_security_posture


class SecurityPostureTests(unittest.TestCase):
    def test_enabled_defender_and_all_firewall_profiles_pass_basic_check(self):
        snapshot = {
            "defender": {
                "AMServiceEnabled": True,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": True,
                "BehaviorMonitorEnabled": True,
                "IoavProtectionEnabled": True,
                "OnAccessProtectionEnabled": True,
                "AntivirusSignatureAge": 1,
            },
            "firewall": [
                {"Name": "Domain", "Enabled": True},
                {"Name": "Private", "Enabled": True},
                {"Name": "Public", "Enabled": True},
            ],
        }
        status, observations = evaluate_security_posture(snapshot)
        self.assertEqual(status, "BASIC CHECKS LOOK ENABLED")
        self.assertTrue(any("Public firewall enabled" in item for item in observations))

    def test_disabled_realtime_protection_needs_attention(self):
        snapshot = {
            "defender": {"RealTimeProtectionEnabled": False},
            "firewall": [{"Name": "Public", "Enabled": True}],
        }
        status, observations = evaluate_security_posture(snapshot)
        self.assertEqual(status, "ATTENTION NEEDED")
        self.assertTrue(any("Real-time protection is disabled" in item for item in observations))

    def test_disabled_firewall_needs_attention(self):
        status, _ = evaluate_security_posture({
            "defender": {},
            "firewall": [{"Name": "Public", "Enabled": False}],
        })
        self.assertEqual(status, "ATTENTION NEEDED")

    def test_missing_status_is_not_reported_as_safe(self):
        status, observations = evaluate_security_posture({})
        self.assertEqual(status, "PARTIAL CHECK")
        self.assertTrue(any(item.startswith("UNKNOWN:") for item in observations))

    def test_old_signatures_need_attention(self):
        status, observations = evaluate_security_posture({
            "defender": {"AntivirusSignatureAge": 8},
            "firewall": [{"Name": "Public", "Enabled": True}],
        })
        self.assertEqual(status, "ATTENTION NEEDED")
        self.assertTrue(any("signatures may be stale" in item for item in observations))


if __name__ == "__main__":
    unittest.main()
