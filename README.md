# NO.1 AntiVirus — Windows Security Lab

NO.1 is an experimental, standard-library-only Python security tool. The goal is to build a serious defensive security project through measurable features, testing, and careful engineering.

**Important:** This project is not currently a full antivirus and has not been independently security-tested. It does not replace Microsoft Defender or another reputable endpoint protection product. Keep Windows Security enabled.

## Current features

- Scan one file or a selected folder.
- Stream file contents instead of loading whole files into memory.
- Compute a full SHA-256 hash for scanned files (when the file is within the 1 GiB per-file limit).
- Heuristics for executable/script extensions and common double-extension disguises.
- Detect the harmless, standard EICAR antivirus test pattern.
- Limited script heuristics for encoded PowerShell and Base64-decoding patterns. These can produce false positives and are not proof of malware.
- Poll selected folders for newly observed and changed files.
- Export the visible scan log to CSV.
- Open Windows Security from the dashboard.

## Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer
- No third-party Python packages required
- No internet connection required to run this basic version after Python is installed

During Python setup, select **Add Python to PATH**.

## Run it

1. Download this repository using **Code → Download ZIP** and extract it.
2. Open the extracted `Cyber-o-virus` folder.
3. Double-click `run.bat`.

Or run this from Command Prompt in the project folder:

```bat
py -3 main.py
```

If the Python launcher is unavailable, try:

```bat
python main.py
```

## Understand scan results

- **WARNING** means one or more configured heuristics matched. It does not prove a file is malicious.
- **NO MATCH*** means these limited checks found nothing. It does not mean the file is safe.
- **SKIPPED** means the file was outside the tool's supported scope or exceeded the 1 GiB limit.
- **ERROR** means the file could not be inspected.

This version does not have a comprehensive malware signature database, cloud reputation, machine-learning model, kernel driver, process-memory inspection, exploit prevention, or reliable ransomware blocking. It does not silently delete or quarantine files.

## Safe-use guidance

- Keep Microsoft Defender real-time protection on and install Windows updates.
- Do not run suspicious files to see what they do.
- Start by scanning a test folder you control, not the entire Windows drive.
- Treat alerts as leads for further investigation, not as a final verdict.
- The folder watcher is polling-based, can miss short-lived changes, and is not a tamper-proof background service.
- The EICAR pattern is a harmless test string, but Windows Security may detect or quarantine files containing it.

## Development priorities

A credible path toward stronger protection includes automated unit tests, signed and regularly updated detection rules, reputation and signature validation, safe quarantine with recovery, reliable event monitoring, performance testing, false-positive measurement, and independent security review. Features should be described as implemented only after they are tested. No product can guarantee perfect detection or honestly claim to beat every antivirus without reproducible independent benchmarks.
