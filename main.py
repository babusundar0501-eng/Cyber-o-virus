"""NO.1 AntiVirus — ClamAV-powered cross-platform desktop scanner."""
from __future__ import annotations

import os
import queue
import stat
import sys
import threading
import time
import ctypes
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from platform_support import capability_summary
from clamav_engine import find_clamscan, inspect_file, scan_with_clamav
from quarantine import quarantine_file, restore_file

APP_NAME = "NO.1 AntiVirus"
FONT = "Cambria"
POLL_SECONDS = 3


class NoOneApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1280x820")
        self.root.minsize(900, 650)
        self.root.configure(bg="#101114")
        self.events: queue.Queue = queue.Queue()
        self.watch_roots: list[Path] = []
        self.monitoring = False
        self.monitor_thread: threading.Thread | None = None
        self.seen: dict[str, tuple[int, int]] = {}
        self.pending: dict[str, tuple[tuple[int, int], int]] = {}
        self.baseline_complete = False
        self.scan_count = 0
        self.alert_count = 0
        self.engine_counts = {}
        self.engine_labels: dict[str, ttk.Label] = {}
        self._style()
        self._build()
        if find_clamscan():
            self.clamav_status.configure(text="ClamAV detected · ready to scan", fg="#72d6ad")
        else:
            self.clamav_status.configure(text="ClamAV not found · install ClamAV to enable scanning", fg="#ff9b9b")
        self.root.after(150, self._drain_events)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#0b1020")
        style.configure("Card.TFrame", background="#121b2e", relief="flat")
        style.configure("TLabel", background="#0b1020", foreground="#e8eefb", font=(FONT, 10))
        style.configure("Muted.TLabel", background="#121b2e", foreground="#8fa1bd", font=(FONT, 9))
        style.configure("CardTitle.TLabel", background="#121b2e", foreground="#8fa1bd", font=("Cambria", 9, "bold"))
        style.configure("Metric.TLabel", background="#121b2e", foreground="#ffffff", font=("Cambria", 23, "bold"))
        style.configure("Treeview", background="#101a2b", fieldbackground="#101a2b", foreground="#e8eefb",
                        rowheight=34, borderwidth=0, font=("Cambria", 9))
        style.configure("Treeview.Heading", background="#1a2941", foreground="#b9c9e2",
                        relief="flat", font=("Cambria", 9, "bold"), padding=(8, 10))
        style.map("Treeview", background=[("selected", "#234a70")], foreground=[("selected", "#ffffff")])
        style.configure("Vertical.TScrollbar", background="#17243a", troughcolor="#0e1727", borderwidth=0)

    def _build(self) -> None:
        self.root.configure(bg="#0b1020")
        header = tk.Frame(self.root, bg="#0b1020", padx=28, pady=20)
        header.pack(fill="x")
        brand = tk.Frame(header, bg="#0b1020")
        brand.pack(side="left")
        tk.Label(brand, text="NO.1", bg="#0b1020", fg="#ffffff",
                 font=("Cambria", 27, "bold")).pack(side="left")
        tk.Label(brand, text="  CLAMAV-POWERED SECURITY", bg="#0b1020", fg="#7794b8",
                 font=("Cambria", 9, "bold")).pack(side="left", pady=(12, 0))
        right = tk.Frame(header, bg="#0b1020")
        right.pack(side="right")
        tk.Label(right, text=capability_summary()["platform"].upper(), bg="#17243a", fg="#a9c9ed",
                 padx=12, pady=7, font=("Cambria", 9, "bold")).pack(side="left", padx=(0, 10))
        self.state_label = tk.Label(right, text="● FOLDER GUARD OFF", bg="#0b1020", fg="#ff8792",
                                    font=("Cambria", 9, "bold"))
        self.state_label.pack(side="left", pady=8)

        hero = tk.Frame(self.root, bg="#13233a", padx=24, pady=20)
        hero.pack(fill="x", padx=24, pady=(0, 18))
        tk.Label(hero, text="ClamAV-powered scanning for your computer.", bg="#13233a", fg="#ffffff",
                 font=("Cambria", 20, "bold")).pack(anchor="w")
        tk.Label(hero, text="Quick, long and whole-PC scans powered by ClamAV virus signatures.",
                 bg="#13233a", fg="#a9bdd8", font=("Cambria", 10)).pack(anchor="w", pady=(5, 0))
        tk.Label(hero, text="CLAMAV SCANNING · FOLDER GUARD USES 3-SECOND POLLING",
                 bg="#13233a", fg="#f4c77b", font=("Cambria", 8, "bold")).pack(anchor="w", pady=(12, 0))

        metrics = ttk.Frame(self.root)
        metrics.pack(fill="x", padx=24, pady=(0, 18))
        self.scans_label = self._metric(metrics, "FILES INSPECTED", "0", 0)
        self.alerts_label = self._metric(metrics, "WARNINGS", "0", 1)
        self.folders_label = self._metric(metrics, "WATCHED FOLDERS", "0", 2)

        content = tk.Frame(self.root, bg="#0b1020")
        content.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        left = tk.Frame(content, bg="#121b2e", width=275, padx=16, pady=16)
        left.pack(side="left", fill="y", padx=(0, 16))
        left.pack_propagate(False)
        tk.Label(left, text="QUICK ACTIONS", bg="#121b2e", fg="#a9bdd8",
                 font=("Cambria", 9, "bold")).pack(anchor="w", pady=(0, 12))

        def action(text, command, primary=False):
            color = "#1e8a70" if primary else "#1b2a42"
            hover = "#27a184" if primary else "#263b5a"
            button = tk.Button(left, text=text, command=command, anchor="w",
                               bg=color, fg="#ffffff", activebackground=hover,
                               activeforeground="#ffffff", relief="flat", bd=0,
                               padx=13, pady=11, cursor="hand2",
                               font=("Cambria", 9, "bold"))
            button.pack(fill="x", pady=4)
            button.bind("<Enter>", lambda _event: button.configure(bg=hover))
            button.bind("<Leave>", lambda _event: button.configure(bg=color))
            return button

        action("QUICK SCAN", lambda: self._start_mode_scan("quick"), True)
        action("LONG SCAN", lambda: self._start_mode_scan("long"))
        action("PC SCAN", lambda: self._start_mode_scan("pc"))
        action("Scan a file", self._pick_file)
        action("Scan a folder", self._pick_folder)
        action("Add folder to Folder Guard", self._add_watch)
        self.monitor_button = action("Start Folder Guard", self._toggle_monitor)
        action("Quarantine selected warning", self._quarantine_selected)
        action("Restore selected file", self._restore_selected)
        action("Export scan report", self._export_report)

        tk.Frame(left, bg="#263650", height=1).pack(fill="x", pady=15)
        tk.Label(left, text="SCAN ENGINE", bg="#121b2e", fg="#a9bdd8",
                 font=("Cambria", 9, "bold")).pack(anchor="w", pady=(0, 8))
        self.engine_labels = {}
        self.clamav_status = tk.Label(left, text="ClamAV is ready when clamscan is installed.", bg="#17243a", fg="#8fa1bd",
                                      font=(FONT, 9), wraplength=225, justify="left", padx=10, pady=10)
        self.clamav_status.pack(fill="x")

        right_panel = tk.Frame(content, bg="#121b2e", padx=15, pady=14)
        right_panel.pack(side="left", fill="both", expand=True)
        title_row = tk.Frame(right_panel, bg="#121b2e")
        title_row.pack(fill="x", pady=(0, 10))
        tk.Label(title_row, text="ACTIVITY & DETECTIONS", bg="#121b2e", fg="#ffffff",
                 font=("Cambria", 12, "bold")).pack(side="left")
        tk.Label(title_row, text="LATEST EVENTS", bg="#121b2e", fg="#8fa1bd",
                 font=("Cambria", 8, "bold")).pack(side="right", pady=3)

        area = tk.Frame(right_panel, bg="#121b2e")
        area.pack(fill="both", expand=True)
        columns = ("time", "status", "file", "details")
        self.table = ttk.Treeview(area, columns=columns, show="headings")
        for col, label in zip(columns, ("TIME", "RESULT", "FILE / LOCATION", "DETECTION EVIDENCE")):
            self.table.heading(col, text=label)
        self.table.column("time", width=145, stretch=False)
        self.table.column("status", width=115, stretch=False)
        self.table.column("file", width=260)
        self.table.column("details", width=390)
        self.table.tag_configure("WARNING", foreground="#ff9b9b")
        self.table.tag_configure("NO MATCH*", foreground="#83d9b3")
        self.table.tag_configure("QUARANTINED", foreground="#f3c77b")
        self.table.tag_configure("ERROR", foreground="#ff9b9b")
        self.table.tag_configure("SCANNING", foreground="#a9c9ed")
        scroll = ttk.Scrollbar(area, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        footer = tk.Label(self.root,
            text="Powered by ClamAV. A clean result is not a guarantee that a file or computer is safe.",
            bg="#0b1020", fg="#8294ae", font=("Cambria", 8))
        footer.pack(anchor="w", padx=27, pady=(0, 12))

    def _metric(self, parent: ttk.Frame, title: str, value: str, col: int) -> ttk.Label:
        card = ttk.Frame(parent, style="Card.TFrame", padding=(16, 12))
        card.grid(row=0, column=col, sticky="ew", padx=(0, 12))
        parent.columnconfigure(col, weight=1)
        ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
        label = ttk.Label(card, text=value, style="Metric.TLabel")
        label.pack(anchor="w", pady=(4, 0))
        return label

    def _log(self, status: str, path: str, details: str) -> None:
        self.events.put(("result", status, path, details))

    def _scan_one(self, path: Path) -> None:
        status, findings, _digest = inspect_file(path)
        detail = "; ".join(findings) if findings else ("ClamAV found no detection" if status == "NO MATCH*" else status)
        self._log(status, str(path), detail)

    def _quick_targets(self) -> list[Path]:
        home = Path.home()
        names = ("Desktop", "Downloads", "Documents", "Pictures", "Videos")
        candidates = [base / name for base in (home, home / "OneDrive") for name in names]
        found: list[Path] = []
        seen: set[str] = set()
        for folder in candidates:
            key = os.path.normcase(str(folder))
            if folder.is_dir() and key not in seen:
                found.append(folder)
                seen.add(key)
        return found

    def _pc_targets(self) -> list[Path]:
        if os.name == "nt":
            drives = ctypes.windll.kernel32.GetLogicalDrives()
            fixed = []
            for index in range(26):
                if drives & (1 << index):
                    drive = f"{chr(65 + index)}:\\"
                    if ctypes.windll.kernel32.GetDriveTypeW(drive) == 3:
                        fixed.append(Path(drive))
            return fixed
        if sys.platform == "darwin":
            data_volume = Path("/System/Volumes/Data")
            return [data_volume if data_volume.exists() else Path("/")]
        return [Path("/")]

    def _start_mode_scan(self, mode: str) -> None:
        if mode == "quick":
            targets, label = self._quick_targets(), "Quick scan"
        elif mode == "long":
            targets, label = [Path.home()], "Long scan (user folder)"
        else:
            targets, label = self._pc_targets(), "PC scan (fixed/system storage)"
            if not messagebox.askyesno(APP_NAME, "PC Scan can take a long time and may report access-denied files. For the broadest coverage, run NO.1 with administrator/root permissions. Start PC Scan?"):
                return
        if not targets:
            messagebox.showwarning(APP_NAME, "No scan locations were found for this scan.")
            return
        if not find_clamscan():
            self.clamav_status.configure(text="ClamAV NOT FOUND", fg="#ff9b9b")
            messagebox.showerror(APP_NAME, "ClamAV is not installed or clamscan is not on PATH. Install ClamAV, update its virus database with freshclam, then restart NO.1.")
            return
        self.clamav_status.configure(text=f"ClamAV ready · {label} running", fg="#72d6ad")
        threading.Thread(target=self._scan_paths, args=(targets, label, True), daemon=True).start()

    def _scan_paths(self, targets: list[Path], label: str, recursive: bool = True) -> None:
        self._log("SCANNING", label, "ClamAV scan started: " + ", ".join(str(p) for p in targets))
        code, infected, diagnostic = scan_with_clamav(targets, recursive=recursive)
        for line in infected:
            self._log("WARNING", label, line)
        if code == 0:
            self._log("NO MATCH*", label, "ClamAV completed: no infected files were reported")
        elif code == 1:
            self._log("WARNING", label, f"ClamAV completed and reported {len(infected)} infected result(s)")
        else:
            self._log("ERROR", label, diagnostic or "ClamAV scan failed or could not access the scan locations")

    def _pick_file(self) -> None:
        name = filedialog.askopenfilename(title="Choose a file to inspect")
        if name:
            threading.Thread(target=self._scan_one, args=(Path(name),), daemon=True).start()

    def _pick_folder(self) -> None:
        name = filedialog.askdirectory(title="Choose a folder to scan")
        if name:
            threading.Thread(target=self._scan_folder, args=(Path(name),), daemon=True).start()

    def _scan_folder(self, folder: Path) -> None:
        self._scan_paths([folder], "Selected folder scan", recursive=True)

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
            self.monitor_button.configure(text="Start Folder Guard")
            self.state_label.configure(text="● FOLDER GUARD OFF", fg="#ff8792")
            return
        if self.monitor_thread and self.monitor_thread.is_alive():
            messagebox.showinfo(APP_NAME, "Folder Guard is still stopping. Please wait a moment, then start it again.")
            return
        if not self.watch_roots:
            messagebox.showinfo(APP_NAME, "Add at least one folder to monitor first.")
            self._add_watch()
            if not self.watch_roots:
                return
        self.monitoring = True
        # If this is the first run, build a baseline before reporting new files.
        self.baseline_complete = bool(self.seen)
        self.monitor_button.configure(text="Stop Folder Guard")
        self.state_label.configure(text="● FOLDER GUARD ON", fg="#72d6ad")
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _monitor_loop(self) -> None:
        """Poll watched folders, baseline existing files, and scan stable changes."""
        ignored_dirs = {"$Recycle.Bin", "System Volume Information", ".git", "__pycache__"}
        while self.monitoring:
            for root in list(self.watch_roots):
                if not self.monitoring:
                    break
                try:
                    if root.is_symlink() or not root.is_dir():
                        self._log("ERROR", str(root), "Watch folder is missing or is a symbolic link")
                        continue
                    for base, dirs, files in os.walk(root, followlinks=False):
                        if not self.monitoring:
                            break
                        dirs[:] = [
                            name for name in dirs
                            if name not in ignored_dirs and not (Path(base) / name).is_symlink()
                        ]
                        for filename in files:
                            if not self.monitoring:
                                break
                            path = Path(base) / filename
                            try:
                                if path.is_symlink():
                                    continue
                                info = path.stat(follow_symlinks=False)
                                if not stat.S_ISREG(info.st_mode):
                                    continue
                                key = os.path.normcase(str(path))
                                stamp = (info.st_size, info.st_mtime_ns)
                                previous = self.seen.get(key)

                                # First pass: establish inventory and scan files already present.
                                if not self.baseline_complete:
                                    self.seen[key] = stamp
                                    self._scan_one(path)
                                    continue

                                if previous == stamp:
                                    self.pending.pop(key, None)
                                    continue

                                pending = self.pending.get(key)
                                stable_count = pending[1] + 1 if pending and pending[0] == stamp else 1
                                self.pending[key] = (stamp, stable_count)

                                # Require two identical observations to avoid scanning a file mid-write.
                                if stable_count >= 2:
                                    event = "NEW FILE" if previous is None else "CHANGED"
                                    self.seen[key] = stamp
                                    self.pending.pop(key, None)
                                    self._log(event, str(path), "Stable file change detected by Folder Guard")
                                    self._scan_one(path)
                            except (OSError, PermissionError):
                                continue
                except OSError as exc:
                    self._log("ERROR", str(root), str(exc))

            self.baseline_complete = True
            # Event-driven native monitoring is not yet implemented; this is a 3-second polling guard.
            for _ in range(POLL_SECONDS * 10):
                if not self.monitoring:
                    break
                time.sleep(0.1)

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

    def _quarantine_selected(self) -> None:
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo(APP_NAME, "Select a WARNING row first.")
            return
        values = self.table.item(selected[0], "values")
        if len(values) < 3 or values[1] != "WARNING":
            messagebox.showwarning(APP_NAME, "Only a row marked WARNING can be sent to quarantine.")
            return
        target = Path(values[2])
        prompt = ("Move this file into NO.1 quarantine? This is reversible, but the file "
                  "will no longer be at its original path.\n\n" + str(target))
        if not messagebox.askyesno(APP_NAME, prompt):
            return
        try:
            record = quarantine_file(target)
            self._log("QUARANTINED", str(target), f"Moved to NO.1 quarantine. Restore record: {record}")
            messagebox.showinfo(APP_NAME, f"File moved to NO.1 quarantine.\n\nRestore record:\n{record}")
        except (OSError, ValueError) as exc:
            messagebox.showerror(APP_NAME, f"Quarantine failed safely; check the original file.\n\n{exc}")

    def _restore_selected(self) -> None:
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo(APP_NAME, "Select a QUARANTINED row first.")
            return
        values = self.table.item(selected[0], "values")
        if len(values) < 4 or values[1] != "QUARANTINED":
            messagebox.showwarning(APP_NAME, "Select a row marked QUARANTINED.")
            return
        details = str(values[3])
        marker = "Restore record: "
        if marker not in details:
            messagebox.showerror(APP_NAME, "This row does not contain a restore record.")
            return
        record = Path(details.split(marker, 1)[1])
        if not messagebox.askyesno(APP_NAME, "Restore the quarantined file to its original path? Existing files will never be overwritten."):
            return
        try:
            restored = restore_file(record)
            self._log("RESTORED", str(restored), "NO.1 restored the file and verified its SHA-256.")
            messagebox.showinfo(APP_NAME, f"Restored and hash-verified:\n{restored}")
        except (OSError, ValueError) as exc:
            messagebox.showerror(APP_NAME, f"Restore failed safely.\n\n{exc}")

    def _drain_events(self) -> None:
        try:
            while True:
                _, status, path, details = self.events.get_nowait()
                stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.table.insert("", 0, values=(stamp, status, path, details), tags=(status,))
                if status not in {"WATCH", "ERROR", "SCANNING"}:
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
