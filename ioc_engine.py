"""Local, transparent indicator-of-compromise matching for NO.1 AntiVirus.

Rules are exact SHA-256 hashes and exact file names. This is not a malware
signature database; only add indicators from sources you trust and verify.
"""
from __future__ import annotations

import json
from pathlib import Path

RULES_PATH = Path(__file__).with_name("rules.json")
MAX_RULES_BYTES = 256 * 1024
MAX_RULES = 10_000


def load_rules(path: Path = RULES_PATH) -> tuple[list[dict[str, str]], list[str]]:
    """Load a small JSON rule file and reject malformed or oversized input."""
    try:
        if path.stat().st_size > MAX_RULES_BYTES:
            return [], ["Indicator rules file exceeds the 256 KiB safety limit"]
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], []
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [], [f"Indicator rules could not be loaded: {exc}"]

    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        return [], ["Indicator rules use an unsupported schema"]
    rules = raw.get("rules")
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        return [], ["Indicator rules must be a list of at most 10000 entries"]

    accepted: list[dict[str, str]] = []
    errors: list[str] = []
    for index, item in enumerate(rules):
        if not isinstance(item, dict):
            errors.append(f"Rule {index + 1} is not an object")
            continue
        rule_id = item.get("id")
        description = item.get("description", "Local indicator matched")
        sha256 = item.get("sha256")
        filename = item.get("filename")
        if not isinstance(rule_id, str) or not rule_id.strip() or len(rule_id) > 80:
            errors.append(f"Rule {index + 1} has an invalid id")
            continue
        if not isinstance(description, str) or len(description) > 240:
            errors.append(f"Rule {index + 1} has an invalid description")
            continue
        if sha256 is not None and (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in sha256)
        ):
            errors.append(f"Rule {rule_id} has an invalid SHA-256")
            continue
        if filename is not None and (
            not isinstance(filename, str) or not filename.strip() or len(filename) > 255
        ):
            errors.append(f"Rule {rule_id} has an invalid filename")
            continue
        if sha256 is None and filename is None:
            errors.append(f"Rule {rule_id} has no supported indicator")
            continue
        accepted.append({
            "id": rule_id,
            "description": description,
            "sha256": sha256.lower() if sha256 else "",
            "filename": filename.casefold() if filename else "",
        })
    return accepted, errors


def match_indicators(path: Path, sha256: str, rules_path: Path = RULES_PATH) -> tuple[list[str], list[str]]:
    """Return matching descriptions and rule-file warnings; never execute a file."""
    rules, errors = load_rules(rules_path)
    matched: list[str] = []
    name = path.name.casefold()
    for rule in rules:
        if rule["sha256"] and rule["sha256"] == sha256.lower():
            matched.append(f"Local IOC {rule['id']}: {rule['description']} (SHA-256 match)")
        elif rule["filename"] and rule["filename"] == name:
            matched.append(f"Local IOC {rule['id']}: {rule['description']} (filename match)")
    return matched, errors
