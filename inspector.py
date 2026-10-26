import csv
import hashlib
import io
import json
import os
import platform
import subprocess
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_NAME = "3EN | INSPECTOR"
REPORT_DIR = Path.home() / "Documents" / "3EN_FIGHT_Reports"
SUSPICIOUS_TERMS = (
    "aimbot", "wallhack", "esp", "injector", "memory editor", "cheat engine",
    "mapper", "spoofer", "hwid", "executor", "dll injector", "macro"
)
SCRIPT_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr"}
MAX_RESULTS = 1500
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
INSPECTOR_API_URL = os.environ.get("INSPECTOR_API_URL", "").strip()
SCANNER_API_KEY = os.environ.get("SCANNER_API_KEY", "").strip()


def send_render_report(report):
    """Send a minimal, sanitized summary to the authenticated owner dashboard."""
    if not INSPECTOR_API_URL or not SCANNER_API_KEY:
        return "Not configured; report remains local."
    results = []
    for row in report.get("results", [])[:MAX_RESULTS]:
        if not isinstance(row, dict):
            continue
        flagged = row.get("severity") == "review"
        results.append({
            "file": (str(row.get("check", "")) + " — " + str(row.get("item", "")))[:255],
            "hits": [str(row.get("detail", "Needs review"))[:100]] if flagged else []
        })
    payload = {"player": str(report.get("player", "Unknown"))[:100],
               "total_files": len(results), "results": results}
    url = INSPECTOR_API_URL.rstrip("/")
    if not url.endswith("/api/scan-results"):
        url += "/api/scan-results"
    req = urllib.request.Request(url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Scanner-Key": SCANNER_API_KEY}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8") or "{}")
            if 200 <= response.status < 300 and data.get("ok"):
                return "Uploaded to owner dashboard (report ID: {}).".format(data.get("scan_id", "?"))
            return "Dashboard returned HTTP {}.".format(response.status)
    except Exception as exc:
        return "Dashboard upload failed: {}".format(str(exc)[:250])


def send_discord_report(report, report_path, screenshot_path):
    """Send the report and consented full-screen screenshot to a configured Discord webhook."""
    if not DISCORD_WEBHOOK_URL:
        return False, "DISCORD_WEBHOOK_URL is not configured; report remains local."
    boundary = "----3ENFIGHT" + os.urandom(12).hex()
    payload = {
        "username": "3EN Inspector",
        "embeds": [{
            "title": "🛡️ 3EN | تقرير الفحص الأمني",
            "description": "اكتمل الفحص. النتائج الاحتمالية ليست إثباتًا نهائيًا.",
            "color": 15158332 if report.get("review_count", 0) else 3066993,
            "fields": [
                {"name": "المفتش / اللاعب", "value": str(report.get("player", "غير معروف"))[:200], "inline": True},
                {"name": "الجهاز", "value": str(report.get("device", "غير معروف"))[:200], "inline": True},
                {"name": "عناصر تحتاج مراجعة", "value": str(report.get("review_count", 0)), "inline": True},
                {"name": "إجمالي النتائج", "value": str(report.get("result_count", 0)), "inline": True},
                {"name": "رقم التقرير", "value": str(report.get("run_id", ""))[:100], "inline": False},
                {"name": "وقت الفحص (UTC)", "value": str(report.get("created_at", ""))[:100], "inline": False},
            ],
            "footer": {"text": "3EN • by: ROITH"}
        }]
    }
    parts = []
    def add_field(name, filename, content_type, data):
        parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n").encode("utf-8") + data + b"\r\n")
    parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n").encode("utf-8") + json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\r\n")
    add_field("files[0]", report_path.name, "application/json", report_path.read_bytes())
    if screenshot_path and screenshot_path.exists():
        add_field("files[1]", screenshot_path.name, "image/png", screenshot_path.read_bytes())
    body = b"".join(parts) + f"--{boundary}--\r\n".encode("utf-8")
    req = urllib.request.Request(DISCORD_WEBHOOK_URL, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            if 200 <= response.status < 300:
                return True, "Report and consented screenshot sent to Discord."
            return False, f"Discord returned HTTP {response.status}."
    except Exception as exc:
        return False, f"Discord delivery failed: {exc}"


def capture_full_screen(destination):
    """Capture the entire screen only after the user explicitly opts in."""
    try:
        from PIL import ImageGrab
        image = ImageGrab.grab(all_screens=True)
        image.save(destination, format="PNG")
        return True, "Full-screen screenshot captured after consent."
    except Exception as exc:
        return False, f"Screenshot capture failed: {exc}"


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
        root.geometry("1180x820")
        root.minsize(900, 680)
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
        tk.Label(header, text="3EN", font=("Segoe UI", 28, "bold"), fg="#ff334b", bg="#0d0f15").pack(anchor="w", padx=20, pady=(14, 0))
        tk.Label(header, text="by: ROITH", font=("Segoe UI", 10, "bold"), fg="#a6aab5", bg="#0d0f15").pack(anchor="w", padx=22, pady=(0, 10))
        tk.Label(header, text="INSPECTOR  /  WINDOWS SECURITY & GAME-INTEGRITY REVIEW", fg="#c1c6d4", bg="#0d0f15", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=22, pady=(0, 14))
        tk.Label(root, text="فحص محلي بموافقتك. لا يحذف ملفات ولا يوقف عمليات ولا يرفع محتوى ملفاتك. مؤشرات الغش احتمالية وقد تنتج عنها نتائج إيجابية كاذبة.", wraplength=980, justify="left", fg="#cbd0dc", bg="#08090d").pack(anchor="w", padx=24, pady=(0, 10))
        form = tk.Frame(root, bg="#11141c", highlightbackground="#34303a", highlightthickness=1)
        form.pack(fill="x", padx=18, pady=5)
        tk.Label(form, text="اسم اللاعب / صاحب الجهاز", fg="#f3f4f6", bg="#11141c", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 4))
        self.player = tk.Entry(form, bg="#090b10", fg="#fff", insertbackground="#fff", relief="flat", font=("Segoe UI", 11))
        self.player.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 12), ipady=8)
        form.columnconfigure(0, weight=1)
        self.consent = tk.BooleanVar(value=False)
        tk.Checkbutton(form, text="أوافق على فحص هذا الجهاز محليًا وأفهم طبيعة الفحوصات.", variable=self.consent, bg="#11141c", fg="#f3f4f6", selectcolor="#252530", activebackground="#11141c", activeforeground="white").grid(row=0, column=1, padx=14, pady=(8, 2), sticky="w")
        self.screenshot_consent = tk.BooleanVar(value=False)
        tk.Checkbutton(form, text="أوافق على التقاط صورة لكامل الشاشة وإرسالها مع التقرير إلى Discord.", variable=self.screenshot_consent, bg="#11141c", fg="#ffb7bf", selectcolor="#252530", activebackground="#11141c", activeforeground="white", wraplength=360, justify="left").grid(row=1, column=1, padx=14, pady=(2, 8), sticky="w")
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
        tk.Label(panel, text="نتائج الفحص", fg="#f3f4f6", bg="#11141c", font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(10, 6))
        filterbar = tk.Frame(panel, bg="#11141c")
        filterbar.pack(fill="x", padx=12, pady=(0, 8))
        tk.Label(filterbar, text="بحث:", fg="#aab2c2", bg="#11141c").pack(side="left", padx=(0, 6))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.render_results())
        search_entry = tk.Entry(filterbar, textvariable=self.search_var, bg="#090b10", fg="#f3f4f6", insertbackground="#fff", relief="flat", font=("Segoe UI", 10))
        search_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 10))
        tk.Label(filterbar, text="عرض:", fg="#aab2c2", bg="#11141c").pack(side="left", padx=(0, 6))
        self.filter_var = tk.StringVar(value="الكل")
        self.filter_box = ttk.Combobox(filterbar, textvariable=self.filter_var, values=("الكل", "تحتاج مراجعة", "معلومات فقط"), state="readonly", width=16)
        self.filter_box.pack(side="left")
        self.filter_box.bind("<<ComboboxSelected>>", lambda _event: self.render_results())
        cols = ("severity", "check", "item", "detail")
        self.tree = ttk.Treeview(panel, columns=cols, show="headings")
        for col, title, width in (("severity", "النتيجة", 90), ("check", "نوع الفحص", 150), ("item", "العنصر", 240), ("detail", "التفاصيل", 480)):
            self.tree.heading(col, text=title, command=lambda column=col: self.sort_results(column))
            self.tree.column(col, width=width, minwidth=70, stretch=(col == "detail"))
        self._sort_reverse = {col: False for col in cols}
        self.tree.bind("<Double-1>", lambda _event: self.copy_selected())
        self.tree.tag_configure("review", foreground="#ff9aa6")
        self.tree.tag_configure("info", foreground="#d8deea")
        scrollbar = ttk.Scrollbar(panel, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 10))
        scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=(0, 10))
        footer = tk.Frame(root, bg="#08090d")
        footer.pack(fill="x", padx=18, pady=(0, 12))
        tk.Button(footer, text="فتح مجلد التقارير", command=self.open_reports, bg="#252a36", fg="white", relief="flat", padx=12, pady=7).pack(side="left")
        tk.Button(footer, text="نسخ العنصر المحدد", command=self.copy_selected, bg="#252a36", fg="white", relief="flat", padx=12, pady=7).pack(side="left", padx=8)
        tk.Button(footer, text="تصدير CSV", command=self.export_csv, bg="#252a36", fg="white", relief="flat", padx=12, pady=7).pack(side="left")
        tk.Button(footer, text="تصدير تقرير JSON", command=self.export_report, bg="#c51f36", fg="white", relief="flat", padx=12, pady=7).pack(side="right")

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
        # Screenshot consent is separate from permission to run a local inspection.
        # A user can scan locally without granting permission to capture or upload their screen.
        if self.screenshot_consent.get() and not DISCORD_WEBHOOK_URL:
            messagebox.showwarning("إعدادات الإرسال", "موافقة صورة الشاشة مفعّلة لكن DISCORD_WEBHOOK_URL غير مضبوط. سيُحفظ التقرير والصورة محليًا فقط.")
        elif not DISCORD_WEBHOOK_URL:
            messagebox.showinfo("الفحص المحلي", "لم يتم إعداد إرسال Discord. سيُحفظ التقرير محليًا على هذا الجهاز فقط.")
        self.btn.configure(state="disabled")
        threading.Thread(target=self.worker, args=(player, self.defender_var.get(), self.screenshot_consent.get()), daemon=True).start()

    def worker(self, player, include_defender_scan, capture_screenshot):
        rid = run_id()
        results = perform_scan(self.update_progress, include_defender_scan)
        report_dir = REPORT_DIR
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
            report = {
                "product": "3EN INSPECTOR", "version": "1.0.0",
                "player": player, "run_id": rid, "created_at": datetime.now(timezone.utc).isoformat(),
                "device": platform.node(), "platform": platform.platform(),
                "checks": ["Defender status", "processes and generic cheat indicators", "startup items", "recent temp executables and local SHA-256"] + (["Microsoft Defender Quick Scan request"] if include_defender_scan else []),
                "result_count": len(results), "review_count": sum(1 for x in results if x.get("severity") == "review"),
                "results": results,
                "privacy": "This report may be sent to the configured Discord webhook with a full-screen screenshot only after the user explicitly consents in the app. File contents are not collected.",
                "limitations": "Heuristic indicators are not proof of cheating or malware. This tool is not a substitute for a full antivirus product."
            }
            path = report_dir / f"3EN_FIGHT_{rid}.json"
            path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            screenshot_path = report_dir / f"3EN_FIGHT_{rid}_screen.png" if capture_screenshot else None
            screenshot_status = "Not requested"
            if capture_screenshot:
                ok, screenshot_status = capture_full_screen(screenshot_path)
                if not ok:
                    screenshot_path = None
                report["screenshot_status"] = screenshot_status
                path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            report["dashboard_delivery"] = send_render_report(report)
            sent, delivery_status = send_discord_report(report, path, screenshot_path)
            report["discord_delivery"] = delivery_status
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
        self.render_results()
        self.bar.configure(value=100)
        self.pct.configure(text="100%")
        self.status.configure(text=f"اكتمل الفحص • {report['run_id']}")
        self.total_label.configure(text=str(report["result_count"]))
        self.review_label.configure(text=str(report["review_count"]))
        self.saved_label.configure(text="تم الحفظ")
        self.btn.configure(state="normal", text="↻  إعادة الفحص")
        messagebox.showinfo("اكتمل الفحص", f"حُفظ التقرير محليًا في:\n{path}\n\nإرسال Discord: {report.get('discord_delivery', 'غير معروف')}\nصورة الشاشة: {report.get('screenshot_status', 'لم تُلتقط')}\n\nملاحظة: مؤشرات المراجعة ليست حكمًا نهائيًا.")

    def render_results(self):
        if not hasattr(self, "tree"):
            return
        query = self.search_var.get().strip().casefold() if hasattr(self, "search_var") else ""
        selected = self.filter_var.get() if hasattr(self, "filter_var") else "الكل"
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        for row in getattr(self, "results", []):
            sev = row.get("severity", "info")
            if selected == "تحتاج مراجعة" and sev != "review":
                continue
            if selected == "معلومات فقط" and sev == "review":
                continue
            searchable = " ".join(str(row.get(key, "")) for key in ("check", "item", "detail", "severity")).casefold()
            if query and query not in searchable:
                continue
            self.tree.insert("", "end", values=(("مراجعة" if sev == "review" else "معلومات"), row.get("check", ""), row.get("item", ""), row.get("detail", "")), tags=(sev,))
        if hasattr(self, "status") and hasattr(self, "results"):
            shown = len(self.tree.get_children())
            self.status.configure(text=f"النتائج المعروضة: {shown} من {len(self.results)} • المؤشرات تحتاج مراجعة بشرية")

    def sort_results(self, column):
        reverse = self._sort_reverse.get(column, False)
        rows = [(self.tree.set(item_id, column), item_id) for item_id in self.tree.get_children("")]
        rows.sort(key=lambda pair: pair[0].casefold(), reverse=reverse)
        for index, (_value, item_id) in enumerate(rows):
            self.tree.move(item_id, "", index)
        self._sort_reverse[column] = not reverse

    def copy_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("اختر نتيجة", "حدد نتيجة من الجدول أولًا.")
            return
        values = self.tree.item(selected[0], "values")
        self.root.clipboard_clear()
        self.root.clipboard_append(" | ".join(str(value) for value in values))
        self.status.configure(text="تم نسخ تفاصيل العنصر المحدد.")

    def export_csv(self):
        if not getattr(self, "results", None):
            messagebox.showinfo("لا توجد نتائج", "شغّل الفحص أولًا.")
            return
        destination = filedialog.asksaveasfilename(
            title="تصدير نتائج الفحص CSV",
            defaultextension=".csv",
            initialfile="3EN_FIGHT_results.csv",
            filetypes=[("CSV", "*.csv")]
        )
        if not destination:
            return
        try:
            with open(destination, "w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.DictWriter(stream, fieldnames=("check", "item", "severity", "detail", "sha256"))
                writer.writeheader()
                for row in self.results:
                    writer.writerow({key: row.get(key, "") for key in writer.fieldnames})
            messagebox.showinfo("تم التصدير", "تم حفظ CSV في:\\n" + destination)
        except OSError as exc:
            messagebox.showerror("تعذر التصدير", str(exc))

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
