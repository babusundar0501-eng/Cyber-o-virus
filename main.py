"""NO.0 AntiVirus - experimental lightweight Windows scanner.

Standard-library-only prototype. This is NOT a replacement for Microsoft Defender.
"""
from __future__ import annotations

import hashlib
import os
import queue
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "NO.0 AntiVirus"
POLL_SECONDS = 3
MAX_FILE_BYTES = 50 * 1024 * 1024
RISKY_EXTENSIONS = {
    ".scr", ".pif", ".com", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".hta", ".ps1", ".bat", ".cmd", ".lnk",
}
DOUBLE_EXTENSIONS = {
    ".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".png.exe",
    ".txt.exe", ".xlsx.exe", ".mp4.exe",
}
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_file(path: Path) -> tuple[str, list[str], str]:
    """Return status, findings, SHA-256. Uses simple heuristics, not ML."""
    findings: list[str] = []
    try:
        if not path.is_file():
            return "SKIPPED", ["Not a regular file"], ""
        if path.is_symlink():
            return "SKIPPED", ["Symbolic links are not followed"], ""
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            return "SKIPPED", [f"File exceeds {MAX_FILE_BYTES // (1024 * 1024)} MB scan limit"], ""
        name_lower = path.name.lower()
        if path.suffix.lower() in RISKY_EXTENSIONS:
            findings.append(f"Executable/script type: {path.suffix}")
        if any(name_lower.endswith(ext) for ext in DOUBLE_EXTENSIONS):
            findings.append("Double extension may disguise an executable")
        sample = path.read_bytes()
        if EICAR in sample:
            findings.append("EICAR antivirus test string detected (harmless test pattern)")
        digest = hashlib.sha256(sample).hexdigest()
        return ("WARNING" if findings else "CLEAN*"), findings, digest
    except (OSError, PermissionError) as exc:
        return "ERROR", [str(exc)], ""


class NoZeroApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1000x680")
        self.root.minsize(780, 520)
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
        style.configure("Title.TLabel", font=("Segoe UI", 22, "bold"), foreground="#ffffff")
        style.configure("Sub.TLabel", foreground="#a7a7af")
        style.configure("TButton", font=("Segoe UI", 10), padding=8)
        style.configure("Treeview", background="#191a1f", fieldbackground="#191a1f", foreground="#ededf0", rowheight=26)
        style.configure("Treeview.Heading", background="#27282e", foreground="#ffffff")
        style.map("TButton", background=[("active", "#bd303b")])

    def _build(self) -> None:
        top = ttk.Frame(self.root, padding=(22, 18))
        top.pack(fill="x")
        ttk.Label(top, text="NO.0", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="  /  WINDOWS SECURITY LAB", style="Sub.TLabel").pack(side="left", padx=(8, 0), pady=(8, 0))
        self.state_label = ttk.Label(top, text="● MONITORING OFF", foreground="#ff626b")
        self.state_label.pack(side="right", pady=(8, 0))

        notice = tk.Label(
            self.root,
            text="EXPERIMENTAL PROTOTYPE  •  Keep Microsoft Defender enabled  •  Alerts are heuristic, not proof of malware",
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
        self.monitor_button.pack(side="left")

        area = ttk.Frame(self.root, padding=(22, 0, 22, 12))
        area.pack(fill="both", expand=True)
        columns = ("time", "status", "file", "details")
        self.table = ttk.Treeview(area, columns=columns, show="headings")
        for col, label in zip(columns, ("TIME", "STATUS", "FILE", "DETAILS")):
            self.table.heading(col, text=label)
        self.table.column("time", width=150, stretch=False)
        self.table.column("status", width=100, stretch=False)
        self.table.column("file", width=360)
        self.table.column("details", width=300)
        scroll = ttk.Scrollbar(area, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        bottom = ttk.Label(self.root, text="* CLEAN means no configured heuristic matched; it does not prove a file is safe.", style="Sub.TLabel")
        bottom.pack(anchor="w", padx=24, pady=(0, 14))

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
        detail = "; ".join(findings) if findings else ("No configured heuristic matched" if status == "CLEAN*" else status)
        if digest:
            detail += f" | SHA256 {digest[:16]}…"
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
            self.state_label.configure(text="● MONITORING OFF", foreground="#ff626b")
            return
        if not self.watch_roots:
            messagebox.showinfo(APP_NAME, "Add at least one folder to monitor first.")
            self._add_watch()
            if not self.watch_roots:
                return
        self.monitoring = True
        self.monitor_button.configure(text="Stop monitoring")
        self.state_label.configure(text="● MONITORING ON", foreground="#74e39a")
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
                                if previous is not None and previous != stamp:
                                    self._scan_one(path)
                                elif previous is None:
                                    # First observation establishes baseline; avoid flooding alerts.
                                    continue
                            except OSError:
                                continue
                except OSError as exc:
                    self._log("ERROR", str(root), str(exc))
            time.sleep(POLL_SECONDS)

    def _drain_events(self) -> None:
        try:
            while True:
                kind, status, path, details = self.events.get_nowait()
                stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.table.insert("", 0, values=(stamp, status, path, details))
                self.scan_count += 1 if status not in {"WATCH", "ERROR"} else 0
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
    NoZeroApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
