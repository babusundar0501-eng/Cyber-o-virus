import tempfile
import unittest
from pathlib import Path

from main import EICAR, inspect_file


class InspectFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_ordinary_text_has_no_match_and_hash(self):
        path = self.root / "notes.txt"
        path.write_text("hello NO.1", encoding="utf-8")
        status, findings, digest = inspect_file(path)
        self.assertEqual(status, "NO MATCH*")
        self.assertEqual(findings, [])
        self.assertEqual(len(digest), 64)

    def test_risky_extension_is_flagged(self):
        path = self.root / "script.ps1"
        path.write_text("Write-Output 'hello'", encoding="utf-8")
        status, findings, _ = inspect_file(path)
        self.assertEqual(status, "WARNING")
        self.assertTrue(any("Executable/script type" in item for item in findings))

    def test_double_extension_is_flagged(self):
        path = self.root / "photo.jpg.exe"
        path.write_bytes(b"test")
        status, findings, _ = inspect_file(path)
        self.assertEqual(status, "WARNING")
        self.assertTrue(any("Double extension" in item for item in findings))

    def test_encoded_powershell_pattern_is_flagged(self):
        path = self.root / "script.ps1"
        path.write_bytes(b"powershell.exe -EncodedCommand AAAA")
        status, findings, _ = inspect_file(path)
        self.assertEqual(status, "WARNING")
        self.assertTrue(any("encoded PowerShell" in item for item in findings))

    def test_eicar_test_pattern_is_detected(self):
        path = self.root / "test.txt"
        path.write_bytes(b"prefix " + EICAR + b" suffix")
        status, findings, _ = inspect_file(path)
        self.assertEqual(status, "WARNING")
        self.assertTrue(any("EICAR" in item for item in findings))

    def test_missing_file_returns_error(self):
        status, findings, digest = inspect_file(self.root / "missing.txt")
        self.assertEqual(status, "ERROR")
        self.assertTrue(findings)
        self.assertEqual(digest, "")


if __name__ == "__main__":
    unittest.main()
