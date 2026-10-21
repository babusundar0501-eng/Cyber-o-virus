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


## Cyber-o-virus: No. 1 development roadmap

The goal is to grow Cyber-o-virus into a multi-layered security platform that detects threats, helps prevent damage, responds safely, and supports recovery. The modules below are **proposed future engines**, not claims about features that already exist. Engine names are project identity; protection comes from tested, distinct responsibilities, not the number of modules.

### 1. Ten proposed security engines

| Engine | Intended responsibility | Example measurable work |
| --- | --- | --- |
| **Uncle Engine** | Known-malware indicators and SHA-256 matching | Match verified local hashes and explain the matching rule |
| **Mom Engine** | File reputation and suspicious-file checks | Validate available reputation evidence; clearly label unknown or unavailable reputation |
| **Dad Engine** | Process and system security monitoring | Observe supported Windows security events with least privilege and auditable permissions |
| **Son Engine** | Suspicious scripts and potentially unwanted program (PUP) checks | Detect tested script patterns and explain which rule matched |
| **Daughter Engine** | Browser downloads and file-type checks | Inspect file metadata and mismatches between file extension and content |
| **Baby Engine** | Removable-drive and USB scan workflows | Offer an explicit scan workflow when removable media is selected or attached |
| **Grandpa Engine** | File-integrity monitoring and change detection | Record baseline hashes and report unexpected changes |
| **Grandma Engine** | Scheduled scans and security-configuration audits | Run user-configured scans and report Defender/Firewall posture without silently changing settings |
| **Guardian Engine** | Ransomware-like behavior detection and safe containment | Detect controlled test patterns for unusual mass changes and provide carefully tested response options |
| **Brain Engine** | Correlate findings, reduce duplicate alerts, and prioritize | Combine evidence, preserve each engine's explanation, and test alert priority and false-positive handling |

These engines must not be represented as complete or active until their code, tests, and limitations are documented. Several capabilities require Windows-specific integration and careful permission design.

### 2. Feature priorities

1. **Reliable detection:** verified hash data, metadata and file-type checks, transparent heuristic rules, and clear explanations for every alert.
2. **Real-time visibility:** monitor supported events reliably and respond promptly. A manual scanner or polling folder watcher is not full real-time antivirus protection.
3. **Ransomware safeguards:** detect unusual bulk file changes, protect recovery options, and alert or contain only where technically supported and tested. Never automatically delete personal files merely because a heuristic triggers.
4. **Threat-intelligence updates:** support versioned rules from trusted sources, cryptographic signature verification, expiry, rollback, and safe offline use. Never treat an unsigned download as trusted.
5. **Professional dashboard:** show progress, evidence, severity, affected paths, engine explanations, quarantine/restore state, update health, protection status, and searchable event history.

### 3. Safe response and recovery

- **Quarantine and restore:** use controlled storage, validate paths, preserve original metadata, restrict access where supported, and test restoration before relying on it. Ask for user confirmation for disruptive actions.
- **False-positive review:** let users inspect the evidence and safely restore files they choose to recover; record decisions without treating user overrides as proof that a file is safe.
- **Tamper visibility:** detect and log important configuration changes. Do not promise tamper-proof protection unless it is actually enforced and independently tested.
- **Recovery planning:** document backups, restore procedures, and clear next steps after an alert.
- **Least privilege:** request administrator access only for features that require it; keep scanning and reporting read-only where possible.

Use the [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) as a planning reference for Govern, Identify, Protect, Detect, Respond, and Recover. This reference is guidance, not a certification.

### 4. Testing laboratory

Use an isolated test machine or virtual machine with snapshots and harmless test cases. Do not run live malware on a normal computer. Record reproducible results for:

| Test area | What to measure |
| --- | --- |
| Known, controlled test indicators | Detection accuracy and explanation quality |
| Clean software and documents | False-positive rate |
| Large folders and large files | Scan time, memory use, and reliability |
| Harmless suspicious-behavior simulations | Detection and response accuracy |
| Interrupted, locked, or damaged files | Safe error handling and recovery |
| Outdated or invalid rule data | Clear warnings and safe fallback |
| Quarantine and restoration | Recovery success and preservation of file data |
| File-integrity baselines | Correct change detection and manageable alert noise |

The [official EICAR anti-malware test file](https://www.eicar.org/download-anti-malware-testfile/) can help check basic antivirus handling without using a live virus. It is a test artifact, not a measure of overall protection quality; Windows Security may detect or quarantine it.

Publish test methodology, environment, versions, false positives, missed cases, and performance results. Do not claim a detection rate or superiority without reproducible evidence.

### 5. Delivery phases

**Phase 1 — Reliability:** fix bugs, complete scanning workflows, improve reports, and test every dashboard action.

**Phase 2 — Detection core:** improve hash/indicator handling, file-type and script checks, evidence explanations, and false-positive controls.

**Phase 3 — Protection and recovery:** develop reliable event monitoring, carefully tested quarantine and restore, ransomware-like behavior alerts, and recovery instructions.

**Phase 4 — Security lab:** automate safe tests, measure detection and false positives, and publish repeatable results.

**Phase 5 — Independent validation:** request external security review, compare against established tools using fair methods, and fix discovered weaknesses.

### 6. Definition of progress

Progress means repeatable detection results, low and measured false positives, acceptable performance, secure updates, recoverable response actions, clear limitations, and independent review. No product can honestly guarantee detection of every virus or protection against every attacker. Keep Microsoft Defender real-time protection and Windows Firewall enabled while Cyber-o-virus is under development.

**Implementation status:** this section is a roadmap. The current application does not yet implement all ten proposed engines, comprehensive threat intelligence, full real-time endpoint protection, or reliable ransomware blocking.
