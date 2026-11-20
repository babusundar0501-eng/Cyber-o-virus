import unittest
from platform_support import capability_summary, platform_name


class PlatformSupportTests(unittest.TestCase):
    def test_platform_is_reported(self):
        self.assertTrue(platform_name())

    def test_clamav_engine_is_reported(self):
        summary = capability_summary()
        self.assertEqual(summary["external_antivirus"], "ClamAV is the scanning engine")
        self.assertIn("ClamAV", summary["engine"])


if __name__ == "__main__":
    unittest.main()
