# NO.0 AntiVirus

A lightweight Windows security-learning project. The first version provides a Tkinter dashboard, manual file scanning, basic heuristic warnings, SHA-256 hashes, and polling-based monitoring of selected folders.

> **Important:** NO.0 is an experimental scanner, not a complete antivirus and not a replacement for Microsoft Defender. It does not provide a kernel driver, process-memory scanning, exploit protection, or guaranteed ransomware prevention. Keep Microsoft Defender and Windows Security enabled. Do not use this project as your only protection.

## Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer, installed from the official Python website
- No third-party Python packages required
- Internet is not required after Python is installed

During Python setup, enable **Add Python to PATH**.

## Run it

1. Download this repository using **Code → Download ZIP**, then extract it.
2. Open the extracted `Cyber-o-virus` folder.
3. Double-click `run.bat`.

Or open Command Prompt in the folder and run:

```bat
py -3 main.py
```

If `py` is unavailable, try:

```bat
python main.py
```

## Features

- Scan a file or folder on demand.
- Watch user-selected folders for newly created or changed files.
- Basic heuristics for risky extensions, double extensions, and the harmless EICAR antivirus test string.
- SHA-256 file hashes and an alert log.
- No automatic deletion or silent quarantine.

## Safe use

- Start by scanning a folder containing test files, not your entire Windows drive.
- Heuristic alerts can be false positives. Review results before taking action.
- The EICAR test string is a standard harmless antivirus test pattern; security software may block or quarantine it.
- Folder monitoring uses periodic polling and is not a tamper-proof Windows security service.
- Do not disable Microsoft Defender or run unknown files to test this project.

## Troubleshooting

- **Python was not found:** install Python 3 from the official Python website and enable **Add Python to PATH**, then reopen the terminal.
- **The window opens and closes:** run `py -3 main.py` from Command Prompt to read the error.
- **No third-party dependencies:** this version uses only Python's standard library.
