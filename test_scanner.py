import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from main import inspect_file


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

    def test_missing_file_returns_error(self):
        status, findings, digest = inspect_file(self.root / "missing.txt")
        self.assertEqual(status, "ERROR")
        self.assertTrue(findings)
        self.assertEqual(digest, "")

    def test_base64_decoder_pattern_is_flagged(self):
        path = self.root / "script.ps1"
        path.write_bytes(b"[Convert]::FromBase64String('AAAA')")
        status, findings, _ = inspect_file(path)
        self.assertEqual(status, "WARNING")
        self.assertTrue(any("Base64-decoding" in item for item in findings))

    def test_file_over_scan_limit_is_skipped(self):
        path = self.root / "large.bin"
        path.write_bytes(b"1234")
        with patch("main.MAX_FILE_BYTES", 3):
            status, findings, digest = inspect_file(path)
        self.assertEqual(status, "SKIPPED")
        self.assertTrue(any("safety limit" in item for item in findings))
        self.assertEqual(digest, "")


if __name__ == "__main__":
    unittest.main()
