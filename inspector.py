import csv
import hashlib
import io
import json
import os
import platform
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_NAME = "3EN FIGHT | INSPECTOR TEAM"
REPORT_DIR = Path.home() / "Documents" / "3EN_FIGHT_Reports"
SUSPICIOUS_TERMS = (
    "aimbot", "wallhack", "esp", "injector", "memory editor", "cheat engine",
    "mapper", "spoofer", "hwid", "executor", "dll injector", "macro"
)
SCRIPT_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr"}
MAX_RESULTS = 1500


def run_command(args, timeout=15):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          errors="replace", creationflags=flags, shell=False)


def run_id():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(4).hex().upper()


def item(check, name, detail, severity="info", **extra):
    row = {"check": check, "item": str(name)[:500], "detail": str(detail)[:1000],
           "severity": severity}
    row.update(extra)
    return row


def check_defender_status():
    if os.name != "nt":
        return [item("Windows Security", "Unavailable", "This check is available on Windows only.")]
    try:
        p = run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress"], 15)
        if p.returncode != 0 or not p.stdout.strip():
            return [item("Windows Security", "Status unavailable", (p.stderr or p.stdout or "Defender status could not be read.").strip(), "review")]
        data = json.loads(p.stdout.strip())
        keys = ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled")
        off = [k for k in keys if data.get(k) is False]
        updated = data.get("AntivirusSignatureLastUpdated", "unknown")
        return [item("Windows Security", "Microsoft Defender",
                     ("Protection flags reported disabled: " + ", ".join(off) if off else "Protection flags report enabled") +
                     "; signature last updated: " + str(updated),
                     "review" if off else "info")]
    except Exception as exc:
        return [item("Windows Security", "Status unavailable", str(exc), "review")]


def request_defender_scan():
    """Starts Microsoft's own quick scan only after the user presses the explicit scan button."""
    if os.name != "nt":
        return [item("Microsoft Defender", "Unavailable", "Windows-only feature.")]
    try:
        p = run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Start-MpScan -ScanType QuickScan"], 900)
        if p.returncode == 0:
            return [item("Microsoft Defender", "Quick scan request completed",
                         "Windows accepted the scan command. Check Windows Security for its authoritative findings.")]
        return [item("Microsoft Defender", "Quick scan could not be started",
                     (p.stderr or p.stdout or "No details returned").strip(), "review")]
    except subprocess.TimeoutExpired:
        return [item("Microsoft Defender", "Quick scan timed out",
                     "Check Windows Security for current scan status.", "review")]
    except Exception as exc:
        return [item("Microsoft Defender", "Quick scan unavailable", str(exc), "review")]


def check_processes():
    if os.name != "nt":
        return []
    results = []
    try:
        p = run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"], 30)
        if p.returncode != 0 or not p.stdout.strip():
            return [item("Processes", "Could not enumerate processes", p.stderr or "No data returned", "review")]
        data = json.loads(p.stdout.strip())
        if isinstance(data, dict):
            data = [data]
        for proc in data[:1000]:
            name = proc.get("Name") or "(unknown process)"
            path = proc.get("ExecutablePath") or "path unavailable"
            command = proc.get("CommandLine") or ""
            haystack = (str(name) + " " + str(path) + " " + str(command)).lower()
            matches = [term for term in SUSPICIOUS_TERMS if term in haystack]
            results.append(item("Processes", f"{name} (PID {proc.get('ProcessId', '?')})",
                f"Path: {path}. " + (f"Name/path/command matched generic review terms: {', '.join(matches)}. This is a heuristic and may be a false positive." if matches else "Process observed; presence alone is not evidence of cheating or malware."),
                "review" if matches else "info", pid=proc.get("ProcessId"), path=path))
    except Exception as exc:
        results.append(item("Processes", "Enumeration failed", str(exc), "review"))
    return results


def startup_items():
    results = []
    roots = []
    for env in ("APPDATA", "PROGRAMDATA"):
        value = os.environ.get(env)
        if value:
            roots.append(Path(value) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    for root in roots:
        try:
            for path in root.iterdir():
                results.append(item("Startup", path, "Startup-folder item. Review unfamiliar entries; this alone is not proof of malware.", "review"))
        except (OSError, PermissionError):
            pass
    if os.name == "nt":
        try:
            p = run_command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress"], 25)
            if p.returncode == 0 and p.stdout.strip():
                data = json.loads(p.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                for entry in data[:300]:
                    command = entry.get("Command") or ""
                    haystack = (str(entry.get("Name", "")) + " " + command).lower()
                    matches = [term for term in SUSPICIOUS_TERMS if term in haystack]
                    results.append(item("Startup", entry.get("Name", "Unnamed entry"),
                        f"Command: {command}; Location: {entry.get('Location', 'unknown')}. " +
                        (f"Generic review terms matched: {', '.join(matches)}." if matches else "Review publisher and path if unfamiliar."),
                        "review" if matches else "info"))
        except Exception as exc:
            results.append(item("Startup", "Startup registry query unavailable", str(exc), "info"))
    return results


def recent_temp_executables():
    results, seen = [], set()
    candidates = []
    for env in ("TEMP", "TMP"):
        value = os.environ.get(env)
        if value:
            candidates.append(Path(value))
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(Path(local) / "Temp")
    cutoff = time.time() - 72 * 3600
    for root in candidates:
        try:
            for path in root.iterdir():
                key = str(path).lower()
                if key in seen or not path.is_file() or path.suffix.lower() not in SCRIPT_EXTENSIONS:
                    continue
                seen.add(key)
                try:
                    stat = path.stat()
                    if stat.st_mtime >= cutoff:
                        results.append(item("Recent temporary files", path,
                            f"Executable/script-like file modified {((time.time()-stat.st_mtime)/3600):.1f} hours ago; not proof of malware.",
                            "review", size_bytes=stat.st_size, modified_at=datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()))
                except OSError:
                    pass
        except (OSError, PermissionError):
            pass
    return results[:500]


def hash_suspicious_candidates(results):
    """Hash only already-listed recent temp candidates; never uploads file contents."""
    enriched = []
    for row in results:
        path = row.get("item", "")
        if row.get("check") != "Recent temporary files":
            enriched.append(row)
            continue
        try:
            digest = hashlib.sha256()
            with open(path, "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            row["sha256"] = digest.hexdigest()
            row["detail"] += " SHA-256 calculated locally; no file contents uploaded."
        except (OSError, PermissionError):
            row["detail"] += " SHA-256 unavailable (access denied or file changed)."
        enriched.append(row)
    return enriched


def perform_scan(progress, include_defender_scan):
    checks = [
        ("حالة الحماية", check_defender_status),
        ("العمليات الجارية ومؤشرات الغش العامة", check_processes),
        ("عناصر بدء التشغيل", startup_items),
        ("ملفات مؤقتة حديثة وبصماتها", recent_temp_executables),
    ]
    results = []
    for idx, (label, fn) in enumerate(checks, 1):
        progress(int((idx - 1) * 100 / (len(checks) + (1 if include_defender_scan else 0))), "جاري الفحص: " + label)
        try:
            found = fn()
            if label == "ملفات مؤقتة حديثة وبصماتها":
                found = hash_suspicious_candidates(found)
            results.extend(found)
        except Exception as exc:
            results.append(item(label, "Check failed", str(exc), "review"))
        progress(int(idx * 100 / (len(checks) + (1 if include_defender_scan else 0))), "اكتمل: " + label)
    if include_defender_scan:
        progress(85, "جاري طلب فحص Microsoft Defender — قد يستغرق وقتًا")
        try:
            results.extend(request_defender_scan())
        except Exception as exc:
            results.append(item("Microsoft Defender", "Scan request failed", str(exc), "review"))
        progress(100, "اكتمل الفحص")
    return results[:MAX_RESULTS]


class Inspector:
    def __init__(self, root):
        self.root = root
        self.results = []
        root.title(APP_NAME)
        root.geometry("1060x760")
        root.minsize(800, 620)
        root.configure(bg="#08090d")
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TProgressbar", troughcolor="#252530", background="#ef3348", thickness=16)
        style.configure("Treeview", background="#11141c", fieldbackground="#11141c", foreground="#e5e7eb", rowheight=28, borderwidth=0)
        style.configure("Treeview.Heading", background="#1b202b", foreground="#f3f4f6", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#59202b")])
        header = tk.Frame(root, bg="#0d0f15", highlightbackground="#51212b", highlightthickness=1)
        header.pack(fill="x", padx=18, pady=(18, 10))
        tk.Label(header, text="3EN FIGHT", font=("Segoe UI", 28, "bold"), fg="#ff334b", bg="#0d0f15").pack(anchor="w", padx=20, pady=(14, 0))
        tk.Label(header, text="INSPECTOR TEAM  /  WINDOWS SECURITY & GAME-INTEGRITY REVIEW", fg="#c1c6d4", bg="#0d0f15", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=22, pady=(0, 14))
        tk.Label(root, text="فحص محلي بموافقتك. لا يحذف ملفات ولا يوقف عمليات ولا يرفع محتوى ملفاتك. مؤشرات الغش احتمالية وقد تنتج عنها نتائج إيجابية كاذبة.", wraplength=980, justify="left", fg="#cbd0dc", bg="#08090d").pack(anchor="w", padx=24, pady=(0, 10))
        form = tk.Frame(root, bg="#11141c", highlightbackground="#34303a", highlightthickness=1)
        form.pack(fill="x", padx=18, pady=5)
        tk.Label(form, text="اسم اللاعب / صاحب الجهاز", fg="#f3f4f6", bg="#11141c", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        self.player = tk.Entry(form, bg="#090b10", fg="#fff", insertbackground="#fff", relief="flat", font=("Segoe UI", 11))
        self.player.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 12), ipady=8)
        form.columnconfigure(0, weight=1)
        self.consent = tk.BooleanVar(value=False)
        tk.Checkbutton(form, text="أوافق على فحص هذا الجهاز محليًا وأفهم طبيعة الفحوصات.", variable=self.consent, bg="#11141c", fg="#f3f4f6", selectcolor="#252530", activebackground="#11141c", activeforeground="white").grid(row=0, column=1, rowspan=2, padx=14, pady=10)
        controls = tk.Frame(root, bg="#08090d")
        controls.pack(fill="x", padx=18, pady=8)
        self.defender_var = tk.BooleanVar(value=False)
        tk.Checkbutton(controls, text="طلب تشغيل فحص Microsoft Defender السريع (قد يستغرق وقتًا)", variable=self.defender_var, bg="#08090d", fg="#d1d5db", selectcolor="#252530", activebackground="#08090d", activeforeground="white").pack(side="left", padx=4)
        self.btn = tk.Button(controls, text="▶  بدء الفحص", command=self.start, bg="#c51f36", fg="white", activebackground="#ef3348", activeforeground="white", relief="flat", padx=20, pady=10, font=("Segoe UI", 10, "bold"), cursor="hand2")
        self.btn.pack(side="right", padx=4)
        self.status = tk.Label(root, text="جاهز — وافق على الفحص ثم اضغط بدء الفحص", fg="#c1c6d4", bg="#08090d", anchor="w")
        self.status.pack(fill="x", padx=22, pady=(5, 3))
        progrow = tk.Frame(root, bg="#08090d")
        progrow.pack(fill="x", padx=22)
        self.bar = ttk.Progressbar(progrow, maximum=100)
        self.bar.pack(side="left", fill="x", expand=True, pady=4)
        self.pct = tk.Label(progrow, text="0%", fg="#ff465b", bg="#08090d", width=6, font=("Segoe UI", 10, "bold"))
        self.pct.pack(side="right")
        stats = tk.Frame(root, bg="#08090d")
        stats.pack(fill="x", padx=18, pady=8)
        self.total_label = self.stat_card(stats, "العناصر المسجلة", "0")
        self.review_label = self.stat_card(stats, "تحتاج مراجعة", "0")
        self.saved_label = self.stat_card(stats, "حالة التقرير", "لم يبدأ")
        panel = tk.Frame(root, bg="#11141c", highlightbackground="#34303a", highlightthickness=1)
        panel.pack(fill="both", expand=True, padx=18, pady=(2, 18))
        tk.Label(panel, text="نتائج الفحص", fg="#f3f4f6", bg="#11141c", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 6))
        cols = ("severity", "check", "item", "detail")
        self.tree = ttk.Treeview(panel, columns=cols, show="headings")
        for col, title, width in (("severity", "النتيجة", 90), ("check", "نوع الفحص", 150), ("item", "العنصر", 240), ("detail", "التفاصيل", 480)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, minwidth=70, stretch=(col == "detail"))
        self.tree.tag_configure("review", foreground="#ff9aa6")
        self.tree.tag_configure("info", foreground="#d8deea")
        scrollbar = ttk.Scrollbar(panel, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=(0, 10))
        footer = tk.Frame(root, bg="#08090d")
        footer.pack(fill="x", padx=18, pady=(0, 12))
        tk.Button(footer, text="فتح مجلد التقارير", command=self.open_reports, bg="#252a36", fg="white", relief="flat", padx=12, pady=7).pack(side="left")
        tk.Button(footer, text="تصدير تقرير JSON", command=self.export_report, bg="#252a36", fg="white", relief="flat", padx=12, pady=7).pack(side="left", padx=8)

    def stat_card(self, parent, title, value):
        card = tk.Frame(parent, bg="#11141c", highlightbackground="#34303a", highlightthickness=1)
        card.pack(side="left", fill="x", expand=True, padx=4)
        tk.Label(card, text=title, fg="#aab2c2", bg="#11141c", font=("Segoe UI", 9)).pack(anchor="w", padx=12, pady=(8, 0))
        value_label = tk.Label(card, text=value, fg="#ff465b", bg="#11141c", font=("Segoe UI", 16, "bold"))
        value_label.pack(anchor="w", padx=12, pady=(0, 8))
        return value_label

    def update_progress(self, value, label):
        self.root.after(0, lambda: (self.bar.configure(value=value), self.pct.configure(text=f"{value}%"), self.status.configure(text=label)))

    def start(self):
        if not self.consent.get():
            messagebox.showwarning("الموافقة مطلوبة", "وافق على الفحص قبل البدء.")
            return
        player = self.player.get().strip()
        if not player:
            messagebox.showwarning("اسم مطلوب", "اكتب اسم اللاعب أو صاحب الجهاز أولًا.")
            return
        self.btn.configure(state="disabled")
        threading.Thread(target=self.worker, args=(player, self.defender_var.get()), daemon=True).start()

    def worker(self, player, include_defender_scan):
        rid = run_id()
        results = perform_scan(self.update_progress, include_defender_scan)
        report_dir = REPORT_DIR
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
            report = {
                "product": "3EN FIGHT INSPECTOR TEAM", "version": "1.0.0",
                "player": player, "run_id": rid, "created_at": datetime.now(timezone.utc).isoformat(),
                "device": platform.node(), "platform": platform.platform(),
                "checks": ["Defender status", "processes and generic cheat indicators", "startup items", "recent temp executables and local SHA-256"] + (["Microsoft Defender Quick Scan request"] if include_defender_scan else []),
                "result_count": len(results), "review_count": sum(1 for x in results if x.get("severity") == "review"),
                "results": results,
                "privacy": "Local JSON report only. No automatic upload. File contents are not collected.",
                "limitations": "Heuristic indicators are not proof of cheating or malware. This tool is not a substitute for a full antivirus product."
            }
            path = report_dir / f"3EN_FIGHT_{rid}.json"
            path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            self.report = report
            self.report_path = path
            self.root.after(0, lambda: self.finish(report, path))
        except Exception as exc:
            message = str(exc)
            self.root.after(0, lambda message=message: self.failed(message))

    def finish(self, report, path):
        self.results = report["results"]
        for row in self.tree.get_children():
            self.tree.delete(row)
        for row in self.results:
            sev = row.get("severity", "info")
            self.tree.insert("", "end", values=(("مراجعة" if sev == "review" else "معلومات"), row.get("check", ""), row.get("item", ""), row.get("detail", "")), tags=(sev,))
        self.bar.configure(value=100)
        self.pct.configure(text="100%")
        self.status.configure(text=f"اكتمل الفحص • {report['run_id']}")
        self.total_label.configure(text=str(report["result_count"]))
        self.review_label.configure(text=str(report["review_count"]))
        self.saved_label.configure(text="تم الحفظ")
        self.btn.configure(state="normal", text="↻  إعادة الفحص")
        messagebox.showinfo("اكتمل الفحص", f"حُفظ التقرير محليًا في:\n{path}\n\nملاحظة: مؤشرات المراجعة ليست حكمًا نهائيًا.")

    def failed(self, message):
        self.status.configure(text="تعذر حفظ التقرير")
        self.btn.configure(state="normal")
        messagebox.showerror("خطأ", message)

    def open_reports(self):
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(str(REPORT_DIR))
        else:
            messagebox.showinfo("مجلد التقارير", str(REPORT_DIR))

    def export_report(self):
        if not hasattr(self, "report"):
            messagebox.showinfo("لا يوجد تقرير", "شغّل الفحص أولًا.")
            return
        destination = filedialog.asksaveasfilename(
            title="تصدير تقرير الفحص",
            defaultextension=".json",
            initialfile=self.report_path.name,
            filetypes=[("JSON report", "*.json")]
        )
        if not destination:
            return
        try:
            Path(destination).write_text(json.dumps(self.report, ensure_ascii=False, indent=2), encoding="utf-8")
            messagebox.showinfo("تم التصدير", "تم تصدير التقرير إلى:\n" + destination)
        except OSError as exc:
            messagebox.showerror("تعذر التصدير", str(exc))


if __name__ == "__main__":
    root = tk.Tk()
    app = Inspector(root)
    root.mainloop()
