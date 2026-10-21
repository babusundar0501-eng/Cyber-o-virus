import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from ioc_engine import load_rules, match_indicators


class IocEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rules = self.root / "rules.json"
        self.sample = self.root / "sample.bin"
        self.sample.write_bytes(b"controlled test content")

    def write_rules(self, rules):
        self.rules.write_text(json.dumps({"schema_version": 1, "rules": rules}), encoding="utf-8")

    def test_exact_hash_indicator_matches(self):
        digest = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        self.write_rules([{"id": "TEST-HASH", "description": "controlled test", "sha256": digest}])
        matched, errors = match_indicators(self.sample, digest, self.rules)
        self.assertFalse(errors)
        self.assertEqual(len(matched), 1)
        self.assertIn("SHA-256 match", matched[0])

    def test_filename_indicator_matches_case_insensitively(self):
        self.write_rules([{"id": "TEST-NAME", "filename": "SAMPLE.BIN"}])
        matched, errors = match_indicators(self.sample, "0" * 64, self.rules)
        self.assertFalse(errors)
        self.assertIn("filename match", matched[0])

    def test_invalid_hash_rule_is_rejected(self):
        self.write_rules([{"id": "BAD", "sha256": "not-a-hash"}])
        matched, errors = match_indicators(self.sample, "0" * 64, self.rules)
        self.assertFalse(matched)
        self.assertTrue(errors)

    def test_unsupported_schema_fails_closed(self):
        self.rules.write_text('{"schema_version": 99, "rules": []}', encoding="utf-8")
        rules, errors = load_rules(self.rules)
        self.assertFalse(rules)
        self.assertTrue(errors)

    def test_missing_rule_file_is_optional(self):
        rules, errors = load_rules(self.root / "missing.json")
        self.assertEqual(rules, [])
        self.assertEqual(errors, [])

    def test_oversized_rule_file_is_rejected(self):
        self.rules.write_text(" " * (256 * 1024 + 1), encoding="utf-8")
        rules, errors = load_rules(self.rules)
        self.assertFalse(rules)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
