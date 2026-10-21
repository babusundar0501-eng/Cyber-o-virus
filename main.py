"""NO.1 AntiVirus — experimental Windows security research tool.

Uses Python's standard library only. It is not a replacement for Microsoft Defender.
"""
from __future__ import annotations

import hashlib
import os
import queue
import re
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "NO.1 AntiVirus"
POLL_SECONDS = 3
MAX_FILE_BYTES = 1024 * 1024 * 1024  # 1 GiB safety limit per file
CHUNK_BYTES = 1024 * 1024
RISKY_EXTENSIONS = {
    ".scr", ".pif", ".com", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".hta", ".ps1", ".bat", ".cmd", ".lnk",
}
DOUBLE_EXTENSIONS = (
    ".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".png.exe",
    ".txt.exe", ".xlsx.exe", ".mp4.exe", ".jpeg.exe", ".gif.exe",
)
# Standard harmless antivirus test pattern. This is not live malware.
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SUSPICIOUS_SCRIPT_PATTERNS = (
    (re.compile(rb"powershell(?:\.exe)?[^\r\n]{0,160}-(?:enc|encodedcommand)\b", re.I),
     "Script contains an encoded PowerShell command pattern"),
    (re.compile(rb"frombase64string\s*\(", re.I),
     "Script contains a Base64-decoding pattern"),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_file(path: Path) -> tuple[str, list[str], str]:
    """Return status, findings and SHA-256 using streaming reads and basic heuristics."""
    findings: list[str] = []
    try:
        if path.is_symlink() or not path.is_file():
            return "SKIPPED", ["Not a regular file or symbolic link"], ""
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            return "SKIPPED", [f"File exceeds {MAX_FILE_BYTES // (1024 * 1024)} MiB safety limit"], ""

        lower_name = path.name.lower()
        if path.suffix.lower() in RISKY_EXTENSIONS:
            findings.append(f"Executable/script type: {path.suffix}")
        if any(lower_name.endswith(ext) for ext in DOUBLE_EXTENSIONS):
            findings.append("Double extension may disguise an executable")

        digest = hashlib.sha256()
        tail = b""
        eicar_found = False
        script_sample = bytearray()
        # Stream data so a large file does not have to be loaded into memory.
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                if EICAR in tail + chunk:
                    eicar_found = True
                tail = (tail + chunk)[-(len(EICAR) - 1):]
                if len(script_sample) < 2 * 1024 * 1024:
                    script_sample.extend(chunk[: 2 * 1024 * 1024 - len(script_sample)])

        if eicar_found:
            findings.append("EICAR antivirus test string detected (harmless test pattern)")
        if path.suffix.lower() in {".ps1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".hta", ".wsf"}:
            sample = bytes(script_sample)
            for pattern, description in SUSPICIOUS_SCRIPT_PATTERNS:
                if pattern.search(sample):
                    findings.append(description)

        return ("WARNING" if findings else "NO MATCH*"), findings, digest.hexdigest()
    except (OSError, PermissionError) as exc:
        return "ERROR", [str(exc)], ""


class NoOneApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1120x720")
        self.root.minsize(820, 560)
        self.root.configure(bg="#101114")
        self.events: queue.Queue = queue.Queue()
        self.watch_roots: list[Path] = []
        self.monitoring = False
        self.monitor_thread: threading.Thread | None = None
        self.seen: dict[str, tuple[int, int]] = {}
        self.scan_count = 0
        self.alert_count = 0
        self._style()
        self._build()
        self.root.after(150, self._drain_events)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#101114")
        style.configure("TLabel", background="#101114", foreground="#e8e8ea", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 24, "bold"), foreground="#ffffff")
        style.configure("Sub.TLabel", foreground="#a7a7af")
        style.configure("TButton", font=("Segoe UI", 10), padding=8)
        style.configure("Treeview", background="#191a1f", fieldbackground="#191a1f", foreground="#ededf0", rowheight=26)
        style.configure("Treeview.Heading", background="#27282e", foreground="#ffffff")
        style.map("TButton", background=[("active", "#bd303b")])

    def _build(self) -> None:
        top = ttk.Frame(self.root, padding=(22, 18))
        top.pack(fill="x")
        ttk.Label(top, text="NO.1", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="  /  WINDOWS SECURITY LAB", style="Sub.TLabel").pack(side="left", padx=(8, 0), pady=(10, 0))
        self.state_label = ttk.Label(top, text="MONITORING OFF", foreground="#ff626b")
        self.state_label.pack(side="right", pady=(10, 0))

        notice = tk.Label(
            self.root,
            text="EXPERIMENTAL SECURITY TOOL  |  Keep Microsoft Defender enabled  |  Heuristic alerts are not proof of malware",
            bg="#2a1b1e", fg="#ffb8be", padx=12, pady=9, anchor="w",
            font=("Segoe UI", 9),
        )
        notice.pack(fill="x", padx=22, pady=(0, 14))

        cards = ttk.Frame(self.root, padding=(22, 0))
        cards.pack(fill="x")
        self.scans_label = self._metric(cards, "FILES INSPECTED", "0", 0)
        self.alerts_label = self._metric(cards, "WARNINGS", "0", 1)
        self.folders_label = self._metric(cards, "WATCH FOLDERS", "0", 2)

        buttons = ttk.Frame(self.root, padding=(22, 14))
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Scan file", command=self._pick_file).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Scan folder", command=self._pick_folder).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Add watch folder", command=self._add_watch).pack(side="left", padx=(0, 8))
        self.monitor_button = ttk.Button(buttons, text="Start monitoring", command=self._toggle_monitor)
        self.monitor_button.pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Export report", command=self._export_report).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Open Windows Security", command=self._open_windows_security).pack(side="left")

        area = ttk.Frame(self.root, padding=(22, 0, 22, 12))
        area.pack(fill="both", expand=True)
        columns = ("time", "status", "file", "details")
        self.table = ttk.Treeview(area, columns=columns, show="headings")
        for col, label in zip(columns, ("TIME", "STATUS", "FILE", "FINDINGS / HASH")):
            self.table.heading(col, text=label)
        self.table.column("time", width=150, stretch=False)
        self.table.column("status", width=105, stretch=False)
        self.table.column("file", width=360)
        self.table.column("details", width=440)
        scroll = ttk.Scrollbar(area, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        ttk.Label(
            self.root,
            text="* NO MATCH means only that these limited checks found nothing. It does NOT mean the file is safe.",
            style="Sub.TLabel",
        ).pack(anchor="w", padx=24, pady=(0, 14))

    def _metric(self, parent: ttk.Frame, title: str, value: str, col: int) -> ttk.Label:
        card = ttk.Frame(parent, padding=12, relief="groove")
        card.grid(row=0, column=col, sticky="ew", padx=(0, 10))
        parent.columnconfigure(col, weight=1)
        ttk.Label(card, text=title, style="Sub.TLabel").pack(anchor="w")
        label = ttk.Label(card, text=value, font=("Segoe UI", 19, "bold"))
        label.pack(anchor="w", pady=(4, 0))
        return label

    def _log(self, status: str, path: str, details: str) -> None:
        self.events.put(("result", status, path, details))

    def _scan_one(self, path: Path) -> None:
        status, findings, digest = inspect_file(path)
        detail = "; ".join(findings) if findings else ("No configured check matched" if status == "NO MATCH*" else status)
        if digest:
            detail += f" | SHA256 {digest}"
        self._log(status, str(path), detail)

    def _pick_file(self) -> None:
        name = filedialog.askopenfilename(title="Choose a file to inspect")
        if name:
            threading.Thread(target=self._scan_one, args=(Path(name),), daemon=True).start()

    def _pick_folder(self) -> None:
        name = filedialog.askdirectory(title="Choose a folder to scan")
        if name:
            threading.Thread(target=self._scan_folder, args=(Path(name),), daemon=True).start()

    def _scan_folder(self, folder: Path) -> None:
        for base, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if d not in {"$Recycle.Bin", "System Volume Information"}]
            for filename in files:
                self._scan_one(Path(base) / filename)

    def _add_watch(self) -> None:
        name = filedialog.askdirectory(title="Choose a folder to monitor")
        if name:
            folder = Path(name)
            if folder not in self.watch_roots:
                self.watch_roots.append(folder)
                self.folders_label.configure(text=str(len(self.watch_roots)))
                self._log("WATCH", str(folder), "Folder added; monitoring starts when enabled")

    def _toggle_monitor(self) -> None:
        if self.monitoring:
            self.monitoring = False
            self.monitor_button.configure(text="Start monitoring")
            self.state_label.configure(text="MONITORING OFF", foreground="#ff626b")
            return
        if not self.watch_roots:
            messagebox.showinfo(APP_NAME, "Add at least one folder to monitor first.")
            self._add_watch()
            if not self.watch_roots:
                return
        self.monitoring = True
        self.monitor_button.configure(text="Stop monitoring")
        self.state_label.configure(text="MONITORING ON", foreground="#74e39a")
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _monitor_loop(self) -> None:
        while self.monitoring:
            for root in list(self.watch_roots):
                try:
                    for base, dirs, files in os.walk(root):
                        dirs[:] = [d for d in dirs if d not in {"$Recycle.Bin", "System Volume Information"}]
                        for filename in files:
                            path = Path(base) / filename
                            try:
                                stat = path.stat()
                                key = str(path).lower()
                                stamp = (stat.st_size, stat.st_mtime_ns)
                                previous = self.seen.get(key)
                                self.seen[key] = stamp
                                if previous is None:
                                    self._log("NEW FILE", str(path), "New file observed in watched folder")
                                    self._scan_one(path)
                                elif previous != stamp:
                                    self._log("CHANGED", str(path), "File changed in watched folder")
                                    self._scan_one(path)
                            except OSError:
                                continue
                except OSError as exc:
                    self._log("ERROR", str(root), str(exc))
            time.sleep(POLL_SECONDS)

    def _export_report(self) -> None:
        destination = filedialog.asksaveasfilename(
            title="Export NO.1 scan report",
            defaultextension=".csv",
            filetypes=[("CSV report", "*.csv"), ("Text report", "*.txt")],
        )
        if not destination:
            return
        try:
            import csv
            with open(destination, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow(("Time", "Status", "File", "Details"))
                for item in self.table.get_children(""):
                    writer.writerow(self.table.item(item, "values"))
            messagebox.showinfo(APP_NAME, f"Report saved to:\n{destination}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Could not export report:\n{exc}")

    def _open_windows_security(self) -> None:
        try:
            os.startfile("windowsdefender:")
        except (AttributeError, OSError):
            try:
                subprocess.Popen(["cmd", "/c", "start", "", "ms-settings:windowsdefender"], shell=False)
            except OSError as exc:
                messagebox.showerror(APP_NAME, f"Could not open Windows Security:\n{exc}")

    def _drain_events(self) -> None:
        try:
            while True:
                _, status, path, details = self.events.get_nowait()
                stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.table.insert("", 0, values=(stamp, status, path, details))
                if status not in {"WATCH", "ERROR"}:
                    self.scan_count += 1
                if status == "WARNING":
                    self.alert_count += 1
                self.scans_label.configure(text=str(self.scan_count))
                self.alerts_label.configure(text=str(self.alert_count))
                if status == "WARNING":
                    self.root.bell()
        except queue.Empty:
            pass
        self.root.after(150, self._drain_events)

    def _close(self) -> None:
        self.monitoring = False
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    NoOneApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
