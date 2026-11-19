import tempfile
import unittest
from pathlib import Path

from quarantine import quarantine_file, restore_file, sha256_file


class QuarantineTests(unittest.TestCase):
    def test_quarantine_and_restore_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.txt"
            source.write_bytes(b"NO.1 harmless test data")
            expected = sha256_file(source)
            record = quarantine_file(source, root / "vault")
            self.assertFalse(source.exists())
            restored = restore_file(record)
            self.assertEqual(restored, source)
            self.assertEqual(sha256_file(restored), expected)

    def test_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.txt"
            target.write_text("safe", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            with self.assertRaises(ValueError):
                quarantine_file(link, root / "vault")


if __name__ == "__main__":
    unittest.main()
