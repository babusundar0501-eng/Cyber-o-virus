# NO.1 AntiVirus — independent cross-platform prototype

NO.1 is an experimental security project built around its own Python detection checks. The application does **not** call ClamAV, Microsoft Defender, or another third-party antivirus engine to perform NO.1 scans.

**Important:** This is an early prototype, not a complete or independently validated antivirus product. Its detection coverage is limited. Do not rely on it as your only protection on a computer containing important data. It does not guarantee detection or prevention of malware.

## Current features

- Cross-platform Python/Tkinter desktop interface intended for Windows, macOS, and Linux.
- Scan one file or a selected folder.
- Stream file contents and compute SHA-256 (maximum 1 GiB per file).
- Five internal detection layers: Dad (PE/ELF/Mach-O executable bytes hidden behind document/media extensions), Mom (selected suspicious script patterns), Uncle (local SHA-256 and filename indicators), Son (harmless EICAR test string), and Aunt (double-extension disguise checks).
- Scan findings include the rule/evidence text; heuristic matches can be false positives.
- Redesigned dark desktop dashboard with scan metrics, built-in detection status, activity log, quarantine and restore actions.
- Folder Guard inventories and scans files already present when first enabled, then polls watched folders every three seconds for new or changed regular files. It waits for two matching size/modified-time observations before scanning a changed file, reducing scans of files still being written.
- Folder Guard skips symbolic links and common system/repository folders. It is polling-based protection for selected folders, not kernel-level, system-wide, or guaranteed instant real-time protection.
- Export the visible scan log to CSV.
- Send a selected WARNING file to NO.1's own quarantine after confirmation.
- Restore a selected quarantined file after confirmation, with SHA-256 verification and no-overwrite protection.
- Uses Python standard-library modules only; no third-party antivirus engine or Python package is required.

## Platform requirements

- Windows 10/11, macOS, or a mainstream Linux distribution.
- Python 3.10 or newer.
- Tkinter must be installed with Python. Some Linux distributions package Tkinter separately (often as `python3-tk`).
- No administrator/root permission is required for ordinary user-accessible file scans. Files protected by the operating system may be inaccessible.

The same Python detection core is used across platforms. Static rules now recognize common Windows PE, Linux ELF, and macOS Mach-O executable headers when those bytes appear under common document/media extensions. Script checks include encoded PowerShell, selected dynamic decode/execute patterns, and download-to-execution chains. These are narrow heuristics, can miss malware, and can produce false positives. Ordinary script extensions alone are not treated as malware.

Platform-specific kernel event monitoring, process-memory inspection, process blocking, boot protection, exploit prevention, and system-wide real-time blocking are **not implemented**.

## Run it

### Windows

Double-click `run.bat`, or run:

```powershell
py -3 main.py
```

### macOS and Linux

From the repository folder:

```bash
python3 main.py
```

If Tkinter is missing on Linux, install the Tkinter package supplied by your distribution, then run the command again.

## Quarantine and restore

1. Scan a file or folder.
2. Select a row marked `WARNING`.
3. Choose **Quarantine selected warning** and confirm.
4. To recover it, select its `QUARANTINED` log row and choose **Restore selected quarantine**.

Quarantine moves the file into a per-user NO.1 data directory and stores a JSON restore record. It refuses symbolic links, verifies SHA-256, and refuses to overwrite an existing restore destination. The move uses an atomic same-filesystem operation; if the quarantine directory is on another filesystem, the operation fails rather than silently copying. Keep the restore record and quarantine folder together. This prototype has not received an independent security audit.

## Understand results

- **WARNING** means one or more local rules matched. It is not proof that a file is malicious.
- **NO MATCH*** means only that the currently implemented rules found nothing. It does not mean the file is safe.
- **SKIPPED** means the file was outside the supported scope or exceeded the 1 GiB limit.
- **ERROR** means the file could not be inspected.

The local IOC file `rules.json` starts empty. It accepts exact SHA-256 and filename indicators. A filename match is weak evidence; only add verified indicators from sources you trust. The application does not currently download or cryptographically verify threat-intelligence updates.

The EICAR pattern is a harmless antivirus test string, not live malware. Other checks are deliberately simple heuristics. NO.1 currently has no comprehensive malware signature database, cloud reputation service, validated machine-learning detector, process-memory scanner, kernel driver, exploit prevention, or tested ransomware blocking.

## Tests

Run the standard-library test suite from the repository folder:

```bash
python -m unittest discover -v
```

The tests cover platform reporting, basic quarantine/restore safety, and selected static detection rules. They are not a security certification or a malware-detection benchmark.

## Development priorities

1. Expand detection rules with provenance, versioning, cryptographic signatures, expiry, and rollback.
2. Build a real event-monitoring layer separately for Windows, macOS, and Linux, with least privilege.
3. Add controlled ransomware-behaviour simulations and recovery testing.
4. Measure false positives, missed detections, scan performance, and resource use on clean and controlled test sets.
5. Obtain independent security review before making protection or superiority claims.

NO.1's goal is an independent engine. It may use operating-system APIs to inspect files and receive events, but detection decisions must come from NO.1's own code and verified data. No product can honestly promise to detect every threat.
