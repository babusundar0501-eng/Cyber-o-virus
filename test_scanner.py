import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from clamav_engine import inspect_file, scan_with_clamav


class ClamAVScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sample = self.root / "sample.txt"
        self.sample.write_text("harmless test content", encoding="utf-8")

    @patch("clamav_engine.find_clamscan", return_value=None)
    def test_missing_clamav_is_an_error_not_a_fake_clean_scan(self, _find):
        code, infected, diagnostic = scan_with_clamav([self.sample])
        self.assertEqual(code, 2)
        self.assertEqual(infected, [])
        self.assertIn("ClamAV was not found", diagnostic)

    @patch("clamav_engine.find_clamscan", return_value="/usr/bin/clamscan")
    @patch("clamav_engine.subprocess.run")
    def test_clean_scan_uses_clamav(self, run, _find):
        run.return_value = SimpleNamespace(returncode=0, stdout="")
        status, findings, digest = inspect_file(self.sample)
        self.assertEqual(status, "NO MATCH*")
        self.assertEqual(findings, [])
        self.assertEqual(digest, "")
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/clamscan")
        self.assertIn("--infected", command)
        self.assertNotIn("--recursive", command)

    @patch("clamav_engine.find_clamscan", return_value="/usr/bin/clamscan")
    @patch("clamav_engine.subprocess.run")
    def test_infected_file_is_reported_as_warning(self, run, _find):
        run.return_value = SimpleNamespace(
            returncode=1, stdout=f"{self.sample}: Win.Test.EICAR FOUND\n"
        )
        status, findings, _ = inspect_file(self.sample)
        self.assertEqual(status, "WARNING")
        self.assertIn("EICAR FOUND", findings[0])

    @patch("clamav_engine.find_clamscan", return_value="/usr/bin/clamscan")
    @patch("clamav_engine.subprocess.run")
    def test_clamav_error_is_not_reported_as_clean(self, run, _find):
        run.return_value = SimpleNamespace(returncode=2, stdout="ERROR: Permission denied")
        status, findings, _ = inspect_file(self.sample)
        self.assertEqual(status, "ERROR")
        self.assertIn("Permission denied", findings[0])

    @patch("clamav_engine.find_clamscan", return_value="/usr/bin/clamscan")
    @patch("clamav_engine.subprocess.run")
    def test_folder_scan_is_recursive(self, run, _find):
        run.return_value = SimpleNamespace(returncode=0, stdout="")
        code, infected, _ = scan_with_clamav([self.root], recursive=True)
        self.assertEqual(code, 0)
        self.assertEqual(infected, [])
        self.assertIn("--recursive", run.call_args.args[0])

    def test_missing_path_returns_error(self):
        code, infected, diagnostic = scan_with_clamav([self.root / "missing"])
        self.assertEqual(code, 2)
        self.assertEqual(infected, [])
        self.assertIn("No selected scan locations exist", diagnostic)

    @patch("clamav_engine.find_clamscan", return_value="/usr/bin/clamscan")
    @patch("clamav_engine.subprocess.run", side_effect=OSError("cannot execute"))
    def test_process_launch_failure_is_reported(self, _run, _find):
        code, infected, diagnostic = scan_with_clamav([self.sample])
        self.assertEqual(code, 2)
        self.assertEqual(infected, [])
        self.assertIn("cannot execute", diagnostic)

    def test_symbolic_link_is_not_followed(self):
        link = self.root / "linked.txt"
        try:
            link.symlink_to(self.sample)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic links are unavailable on this system")
        status, findings, _ = inspect_file(link)
        self.assertEqual(status, "SKIPPED")
        self.assertIn("Symbolic links", findings[0])


if __name__ == "__main__":
    unittest.main()
