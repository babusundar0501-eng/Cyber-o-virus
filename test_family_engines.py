import tempfile
import unittest
from pathlib import Path

from family_engines import (
    ENGINE_INFO,
    run_disguise_engine,
    run_executable_disguise_engine,
    run_file_type_engine,
    run_script_engine,
    run_test_signature_engine,
)


class FamilyEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_five_named_engines_are_documented(self):
        self.assertEqual(set(ENGINE_INFO), {"DAD", "MOM", "UNCLE", "SON", "AUNT"})

    def test_dad_engine_flags_script_extension(self):
        findings = run_file_type_engine(self.root / "demo.ps1")
        self.assertTrue(any("[DAD]" in item for item in findings))

    def test_dad_engine_flags_mz_executable_disguised_as_pdf(self):
        findings = run_executable_disguise_engine(self.root / "invoice.pdf", b"MZ" + b"\x00" * 100)
        self.assertTrue(any("disguised" in item for item in findings))

    def test_dad_engine_does_not_flag_normal_pdf_header(self):
        findings = run_executable_disguise_engine(self.root / "invoice.pdf", b"%PDF-1.7")
        self.assertEqual(findings, [])

    def test_dad_engine_does_not_flag_executable_extension_as_disguise(self):
        findings = run_executable_disguise_engine(self.root / "app.exe", b"MZ" + b"\x00" * 100)
        self.assertEqual(findings, [])

    def test_mom_engine_flags_encoded_powershell_pattern(self):
        findings = run_script_engine(self.root / "demo.ps1", b"powershell.exe -EncodedCommand AAAA")
        self.assertTrue(any("[MOM]" in item and "encoded PowerShell" in item for item in findings))

    def test_aunt_engine_flags_double_extension(self):
        findings = run_disguise_engine(self.root / "holiday.jpg.exe")
        self.assertTrue(any("[AUNT]" in item and "Double extension" in item for item in findings))

    def test_son_engine_only_flags_test_signature_when_present(self):
        self.assertEqual(run_test_signature_engine(False), [])
        self.assertTrue(run_test_signature_engine(True)[0].startswith("[SON]"))


if __name__ == "__main__":
    unittest.main()
