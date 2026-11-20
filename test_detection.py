import unittest
from pathlib import Path

from family_engines import (
    run_disguise_engine,
    run_file_type_engine,
    run_script_engine,
    run_test_signature_engine,
)


class StaticDetectionTests(unittest.TestCase):
    def test_detects_pe_content_disguised_as_pdf(self):
        findings = run_file_type_engine(Path("invoice.pdf"), b"MZ" + b"\x00" * 32)
        self.assertTrue(findings)
        self.assertIn("Windows PE-style", findings[0])

    def test_detects_elf_content_disguised_as_image(self):
        findings = run_file_type_engine(Path("photo.jpg"), b"\x7fELF" + b"\x00" * 32)
        self.assertTrue(findings)
        self.assertIn("ELF executable", findings[0])

    def test_does_not_flag_plain_text_document_by_extension_alone(self):
        self.assertEqual(run_file_type_engine(Path("notes.txt"), b"ordinary notes"), [])

    def test_detects_suspicious_encoded_powershell_pattern(self):
        sample = b"powershell.exe -EncodedCommand AAAA"
        findings = run_script_engine(Path("sample.ps1"), sample)
        self.assertTrue(findings)
        self.assertIn("[MOM]", findings[0])

    def test_eicar_label_is_explicitly_harmless_test(self):
        findings = run_test_signature_engine(True)
        self.assertIn("harmless test pattern", findings[0])

    def test_double_extension_is_a_heuristic_warning(self):
        self.assertTrue(run_disguise_engine(Path("invoice.pdf.exe")))


if __name__ == "__main__":
    unittest.main()
