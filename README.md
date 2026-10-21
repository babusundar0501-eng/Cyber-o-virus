# NO.1 AntiVirus — Windows Security Lab

NO.1 is an experimental, standard-library-only Python security tool. The goal is to build a serious defensive security project through measurable features, testing, and careful engineering.

**Important:** This project is not currently a full antivirus and has not been independently security-tested. It does not replace Microsoft Defender or another reputable endpoint protection product. Keep Windows Security enabled.

## Current features

- Scan one file or a selected folder.
- Stream file contents instead of loading whole files into memory.
- Compute a full SHA-256 hash for scanned files (when the file is within the 1 GiB per-file limit).
- Five clearly named local detection-family layers in the dashboard: Dad (file type and executable-disguise checks), Mom (limited suspicious script patterns), Uncle (local indicator rules), Son (harmless EICAR test signature), and Aunt (double-extension disguise checks). These are specialized checks inside NO.1, not five third-party antivirus products.
- Detect a Windows PE-style `MZ` header when it appears in files named with common document, image, audio, video, or text extensions. This is a low-cost disguise heuristic, not full file-format validation.
- Detect the harmless, standard EICAR antivirus test pattern.
- Limited script heuristics for encoded PowerShell and Base64-decoding patterns. These can produce false positives and are not proof of malware.
- Local indicator matching for exact SHA-256 hashes and exact file names, configured in `rules.json` and validated before use.
- Live family dashboard counters show which local detection layer produced findings during scans.
- Poll selected folders for newly observed and changed files.
- Export the visible scan log to CSV.
- Start Microsoft Defender quick scans and custom folder scans from the dashboard (Windows only).
- Read Defender service, antivirus, real-time, behavior-monitoring, downloaded-file and on-access protection indicators (Windows only; read-only).
- Check Windows Firewall Domain, Private and Public profiles plus Defender signature age; show attention warnings for disabled protections or potentially stale signatures (read-only).
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

NO.1's own detection is still heuristic and limited. The local IOC engine matches only exact SHA-256 hashes and exact filenames supplied in `rules.json`; the starter rule list is empty, rules are not automatically downloaded or cryptographically signed, and a filename match alone is weak evidence. Only add indicators from sources you trust. The optional Defender buttons ask the Microsoft Defender installation on the PC to run its native quick/custom scan; they do not turn NO.1's own heuristics into a full antivirus engine. The security-posture check only reads Defender and Windows Firewall status and reports visible indicators; it does not repair settings, guarantee firewall policy correctness, or prove the computer is clean. Scan permissions and results depend on Windows Security configuration. This project itself does not have a comprehensive independent malware signature database, cloud reputation, machine-learning model, kernel driver, process-memory inspection, exploit prevention, or reliable ransomware blocking. It does not silently delete or quarantine files.

## Local indicator rules

The optional `rules.json` file uses schema version 1. It starts empty so the application does not pretend to ship with a comprehensive threat-intelligence feed. Example format:

```json
{
  "schema_version": 1,
  "rules": [
    {
      "id": "EXAMPLE-HASH",
      "description": "Description from a trusted source",
      "sha256": "replace-with-a-real-64-character-sha256-hash"
    },
    {
      "id": "EXAMPLE-NAME",
      "description": "Filename indicator from a trusted source",
      "filename": "example-suspicious-file.exe"
    }
  ]
}
```

The example hash is a placeholder and will be rejected until replaced with a valid SHA-256 value. You can use `sha256`, `filename`, or both. Rules are local and never execute matched files. A match is an indicator, not proof of maliciousness; filenames can be changed and legitimate files can share a name. Malformed rules are reported instead of being silently trusted.

Run the automated tests from the project folder with:

```bat
py -3 -m unittest discover -v
```

## Safe-use guidance

- Keep Microsoft Defender real-time protection on and install Windows updates.
- Do not run suspicious files to see what they do.
- Start by scanning a test folder you control, not the entire Windows drive.
- Treat alerts as leads for further investigation, not as a final verdict.
- The folder watcher is polling-based, can miss short-lived changes, and is not a tamper-proof background service.
- The EICAR pattern is a harmless test string, but Windows Security may detect or quarantine files containing it.

## Development priorities

The family labels are organizational names for five small checks, not independent antivirus vendors or full AV engines. Dashboard finding counters are cumulative during the current session. A credible path toward stronger protection includes signed and regularly updated detection rules, reputation and signature validation, carefully tested quarantine with recovery, reliable event monitoring, performance testing, false-positive measurement, and independent security review. Features should be described as implemented only after they are tested. No product can guarantee perfect detection or honestly claim to beat every antivirus without reproducible independent benchmarks.
