# NO.1 AntiVirus — ClamAV-powered desktop scanner

NO.1 is a cross-platform desktop interface that runs the real **ClamAV** antivirus command-line scanner (\`clamscan\`). ClamAV performs file scanning using its virus signatures and detection engine. NO.1 does not claim that its previous experimental Python heuristics are a replacement for ClamAV.

**Important:** ClamAV is a signature-based scanner, not a guarantee of complete protection. Detection depends on the installed ClamAV version and current virus databases. Keep your existing operating-system security protections enabled. NO.1 is an experimental desktop scanner, not a kernel-level or fully managed endpoint-protection product.

## Features

- Cambria typography throughout the desktop interface.
- **Quick Scan:** scans existing Desktop, Downloads, and Documents folders for the current user.
- **Long Scan:** recursively scans the current user's home folder.
- **PC Scan:** scans fixed Windows drives, the macOS Data volume, or the Linux root filesystem. It can take a long time and may need administrator/root permissions to read protected files.
- Scan a selected file or folder.
- Folder Guard polls selected folders every three seconds and calls ClamAV when it detects new or changed stable files. This is polling-based and is not instant, system-wide protection.
- ClamAV infected results appear as WARNING rows. ClamAV errors and missing scanner installations appear as ERROR messages; NO.1 does not fake a clean result when ClamAV is unavailable.
- Quarantine selected warning files after confirmation; restore them with SHA-256 verification and no-overwrite protection.
- Export the visible scan log to CSV.
- Uses Python standard-library modules only. ClamAV itself is a separate required installation.

## Requirements

- Windows 10/11, macOS, or mainstream Linux.
- Python 3.10 or newer with Tkinter.
- ClamAV installed, with \`clamscan\` available on PATH (Windows also checks the usual Program Files installation folders).
- Updated ClamAV virus database. Run \`freshclam\` after installing, following the platform's ClamAV setup instructions.

### Install ClamAV

- **Windows:** install the official ClamAV Windows distribution, then ensure the folder containing \`clamscan.exe\` is on PATH. Run \`freshclam.exe\` to download/update signatures if it is included in the distribution.
- **macOS (Homebrew):** \`brew install clamav\`, configure the ClamAV database settings as required by the installed package, then run \`freshclam\`.
- **Debian/Ubuntu:** \`sudo apt install clamav clamav-freshclam\`, then update definitions with \`sudo freshclam\`.

The exact installation steps can vary by ClamAV release and operating system. NO.1 checks for \`clamscan\` when a scan starts and displays an error if it cannot find it.

## Run NO.1

### Windows

Double-click \`run.bat\`, or run:

\`\`\`powershell
py -3 main.py
\`\`\`

### macOS and Linux

From the repository folder:

\`\`\`bash
python3 main.py
\`\`\`

If Tkinter is missing on Linux, install the Tkinter package supplied by your distribution (commonly \`python3-tk\`).

## Scan modes and coverage

- **Quick Scan** covers the current user's Desktop, Downloads, and Documents folders that exist.
- **Long Scan** covers the current user's home directory, including nested folders.
- **PC Scan** covers fixed drives on Windows, the Data volume on macOS, or \`/\` on Linux. It excludes volatile pseudo-filesystem locations such as \`/proc\`, \`/sys\`, \`/dev\`, and \`/run\` on Unix-like systems. Protected files may not be readable unless NO.1 is run with sufficient privileges.
- ClamAV is configured with a 1 GiB maximum file size and 4 GiB maximum scan size per scan target to limit resource use. Files beyond ClamAV's configured limits may not be inspected.

A clean scan means ClamAV did not report an infection in the files it was able to inspect with its current definitions. It does **not** prove that the computer is malware-free.

## Folder Guard

Folder Guard inventories and scans files already present when first enabled, then polls selected folders every three seconds for new or changed regular files. It waits for two identical size/modified-time observations before scanning a changed file, reducing scans of files still being written. It skips symbolic links and common system/repository folders. Files created and deleted between polling passes can be missed.

Folder Guard is not a native filesystem event monitor, kernel driver, process blocker, boot-time scanner, exploit-prevention system, or complete real-time protection.

## Quarantine and restore

1. Scan a file or folder.
2. Select a row marked \`WARNING\`.
3. Choose **Quarantine selected warning** and confirm.
4. To recover it, select its \`QUARANTINED\` log row and choose **Restore selected file**.

Quarantine moves the file into a per-user NO.1 data directory and stores a JSON restore record. It refuses symbolic links, verifies SHA-256, and refuses to overwrite an existing restore destination. Keep the restore record and quarantine folder together. This prototype has not received an independent security audit.

## Tests

Run:

\`\`\`bash
python -m unittest discover -v
\`\`\`

Tests mock ClamAV process results and do not download malware or require a live ClamAV installation. Passing tests do not constitute a security certification or malware-detection benchmark.
