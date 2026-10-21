"""Read-only Windows security posture evaluation for NO.1.

This module evaluates status returned by Windows PowerShell cmdlets. It does not
change Defender, firewall, registry, or account settings.
"""
from __future__ import annotations


def evaluate_security_posture(snapshot: dict) -> tuple[str, list[str]]:
    """Return (overall label, human-readable observations) for a Windows status snapshot."""
    observations: list[str] = []
    defender = snapshot.get("defender") or {}
    firewall = snapshot.get("firewall") or []

    checks = (
        ("AMServiceEnabled", "Microsoft Defender service"),
        ("AntivirusEnabled", "Microsoft Defender antivirus"),
        ("RealTimeProtectionEnabled", "Real-time protection"),
        ("BehaviorMonitorEnabled", "Behavior monitoring"),
        ("IoavProtectionEnabled", "Downloaded-file scanning"),
        ("OnAccessProtectionEnabled", "On-access protection"),
        ("AntivirusSignatureAge", "Antivirus signature age (days)"),
    )
    failed = 0
    for key, label in checks:
        if key == "AntivirusSignatureAge":
            age = defender.get(key)
            if isinstance(age, (int, float)):
                observations.append(f"{label}: {age}")
                if age > 3:
                    observations.append("WARNING: Defender signatures may be stale; update them in Windows Security.")
                    failed += 1
            else:
                observations.append(f"{label}: unavailable")
            continue
        value = defender.get(key)
        if value is True:
            observations.append(f"OK: {label} enabled")
        elif value is False:
            observations.append(f"WARNING: {label} is disabled")
            failed += 1
        else:
            observations.append(f"UNKNOWN: {label} status unavailable")

    if not firewall:
        observations.append("UNKNOWN: Windows Firewall profile status unavailable")
    else:
        for profile in firewall:
            name = str(profile.get("Name", "Unknown"))
            enabled = profile.get("Enabled")
            if enabled is True:
                observations.append(f"OK: {name} firewall enabled")
            elif enabled is False:
                observations.append(f"WARNING: {name} firewall is disabled")
                failed += 1
            else:
                observations.append(f"UNKNOWN: {name} firewall status unavailable")

    if failed:
        return "ATTENTION NEEDED", observations
    if any(item.startswith("UNKNOWN:") for item in observations):
        return "PARTIAL CHECK", observations
    return "BASIC CHECKS LOOK ENABLED", observations
