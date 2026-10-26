# 3eN Fight Scanner PRO - local Windows scanner
# Scans only folders explicitly selected by the user.
# Reports matching file names and SHA-256 hashes to the configured admin endpoint.

import hashlib
import json
import os
import threading
import urllib.error
import urllib.request
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog

APP_NAME = "3eN Fight Scanner PRO"
DEFAULT_ENDPOINT = "https://YOUR-RENDER-SERVICE.onrender.com"
MAX_RESULTS = 5000
MAX_FILES = 100000

# These are review indicators, not proof of cheating. Update this list only
# with indicators you have a reliable reason to investigate.
INDICATORS = (
    "eulen", "menyo", "tiago", "falloutmenu", "cobra", "lux menu",
    "luxmenu", "dopamine", "lua executor", "injector", "extreme injector",
    "gh injector", "cheatengine", "cheat engine", "redengine", "red engine",
    "phantom", "zentrix", "zc-firerate", "no_recoil", "cr-fastrun",
    "loader"
)

def match_indicators(filename):
    lower = filename.casefold()
    return [indicator for indicator in INDICATORS if indicator.casefold() in lower]

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

class ScannerApp:
    def __init__(self, root):
        self.root = root
        root.title(APP_NAME)
        root.geometry("780x600")
        root.minsize(680, 520)
        root.configure(bg="#08090d")
        self.folders = []
        self.scanning = False

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#08090d")
        style.configure("TLabel", background="#08090d", foreground="#f5f3f4", font=("Segoe UI", 10))
        style.configure("Title.TLabel", foreground="#ff304f", font=("Segoe UI", 20, "bold"))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("Horizontal.TProgressbar", troughcolor="#1c1c24", background="#ff304f")

        outer = ttk.Frame(root, padding=22)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="3eN  /  FIGHT SCANNER PRO", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="LOCAL FILE INSPECTOR  •  BY ROITH").pack(anchor="w", pady=(2, 18))

        form = ttk.Frame(outer)
        form.pack(fill="x")
        ttk.Label(form, text="اسم اللاعب / صاحب الجهاز:").grid(row=0, column=0, sticky="w", pady=5)
        self.player = tk.StringVar()
        ttk.Entry(form, textvariable=self.player, width=48).grid(row=0, column=1, sticky="ew", padx=10, pady=5)

        ttk.Label(form, text="رابط موقع Render:").grid(row=1, column=0, sticky="w", pady=5)
        self.endpoint = tk.StringVar(value=DEFAULT_ENDPOINT)
        ttk.Entry(form, textvariable=self.endpoint).grid(row=1, column=1, sticky="ew", padx=10, pady=5)

        ttk.Label(form, text="مفتاح أداة الفحص (SCANNER_API_KEY):").grid(row=2, column=0, sticky="w", pady=5)
        self.api_key = tk.StringVar()
        ttk.Entry(form, textvariable=self.api_key, show="•").grid(row=2, column=1, sticky="ew", padx=10, pady=5)
        form.columnconfigure(1, weight=1)

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(16, 10))
        ttk.Button(buttons, text="اختيار مجلد", command=self.add_folder).pack(side="left")
        ttk.Button(buttons, text="مسح القائمة", command=self.clear_folders).pack(side="left", padx=8)
        self.scan_button = ttk.Button(buttons, text="بدء الفحص", command=self.start_scan)
        self.scan_button.pack(side="right")

        self.folder_text = tk.Text(outer, height=5, bg="#101015", fg="#d7cbd0", insertbackground="white",
                                   relief="flat", highlightthickness=1, highlightbackground="#33212a")
        self.folder_text.pack(fill="x", pady=(0, 12))
        self.folder_text.insert("end", "اختر مجلدات FiveM أو GTA V التي لديك صلاحية لفحصها. لن يبدأ الفحص قبل اختيار المجلدات.")
        self.folder_text.configure(state="disabled")

        self.progress = ttk.Progressbar(outer, mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=5)
        self.status = tk.StringVar(value="جاهز — لا يبدأ إرسال أي تقرير إلا بعد انتهاء الفحص وموافقتك.")
        ttk.Label(outer, textvariable=self.status, wraplength=720).pack(anchor="w", pady=5)

        self.output = tk.Text(outer, height=10, bg="#0e0e13", fg="#e6dfe3", insertbackground="white",
                              relief="flat", highlightthickness=1, highlightbackground="#33212a")
        self.output.pack(fill="both", expand=True, pady=(8, 0))
        self.output.insert("end", "تنبيه: المؤشرات قد تنتج عنها نتائج خاطئة؛ راجع كل نتيجة يدويًا.\n")
        self.output.configure(state="disabled")
        self.results = []
        self.total_files = 0

    def log(self, text):
        self.output.configure(state="normal")
        self.output.insert("end", text + "\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def refresh_folders(self):
        self.folder_text.configure(state="normal")
        self.folder_text.delete("1.0", "end")
        self.folder_text.insert("end", "\n".join(self.folders) if self.folders else "لم يتم اختيار مجلدات بعد.")
        self.folder_text.configure(state="disabled")

    def add_folder(self):
        folder = filedialog.askdirectory(title="اختر مجلدًا لفحصه")
        if folder and folder not in self.folders:
            self.folders.append(folder)
            self.refresh_folders()

    def clear_folders(self):
        if not self.scanning:
            self.folders = []
            self.refresh_folders()

    def start_scan(self):
        if self.scanning:
            return
        if not self.folders:
            messagebox.showwarning(APP_NAME, "اختر مجلدًا واحدًا على الأقل.")
            return
        if not self.player.get().strip():
            messagebox.showwarning(APP_NAME, "اكتب اسم اللاعب أو صاحب الجهاز.")
            return
        self.scanning = True
        self.scan_button.configure(state="disabled")
        self.results = []
        self.total_files = 0
        self.progress.configure(value=0)
        self.log("بدأ الفحص المحلي. لا تغلق البرنامج...")
        threading.Thread(target=self.scan_worker, daemon=True).start()

    def scan_worker(self):
        errors = 0
        for folder in list(self.folders):
            for current, dirs, files in os.walk(folder):
                dirs[:] = [d for d in dirs if d.casefold() not in {
                    "node_modules", ".git", "__pycache__", "cache"
                }]
                for filename in files:
                    if self.total_files >= MAX_FILES:
                        self.root.after(0, self.log, f"وصل الفحص إلى حد {MAX_FILES:,} ملف لحماية الأداء.")
                        break
                    self.total_files += 1
                    path = os.path.join(current, filename)
                    hits = match_indicators(filename)
                    if hits:
                        try:
                            file_hash = sha256_file(path)
                            size = os.path.getsize(path)
                            hits = hits + [f"SHA-256: {file_hash}", f"الحجم بالبايت: {size}"]
                            relative = os.path.relpath(path, folder)
                            self.results.append({"file": relative[:255], "hits": hits})
                        except (OSError, PermissionError):
                            errors += 1
                    if self.total_files % 100 == 0:
                        self.root.after(0, self.status.set, f"تم فحص {self.total_files:,} ملف — {len(self.results)} ملف عليه مؤشر")
            if self.total_files >= MAX_FILES:
                break

        self.root.after(0, self.scan_finished, errors)

    def scan_finished(self, errors):
        self.scanning = False
        self.scan_button.configure(state="normal")
        self.progress.configure(value=100)
        self.log(f"اكتمل الفحص: {self.total_files:,} ملف، {len(self.results)} نتيجة، {errors} ملف تعذر قراءته.")
        self.status.set(f"اكتمل الفحص المحلي — إجمالي الملفات: {self.total_files:,} — مؤشرات: {len(self.results)}")
        if not messagebox.askyesno(APP_NAME, "اكتمل الفحص. هل تريد إرسال التقرير إلى لوحة الإدارة؟\n\nسيتم إرسال أسماء الملفات المطابقة ومؤشراتها وبصمات SHA-256 الخاصة بها فقط."):
            self.log("لم يتم إرسال التقرير.")
            return
        threading.Thread(target=self.send_report, daemon=True).start()

    def send_report(self):
        endpoint = self.endpoint.get().strip().rstrip("/")
        api_key = self.api_key.get().strip()
        if not endpoint.startswith("https://") or "YOUR-RENDER-SERVICE" in endpoint or not api_key:
            self.root.after(0, messagebox.showerror, APP_NAME,
                            "أدخل رابط Render الحقيقي (https://...) ومفتاح SCANNER_API_KEY.")
            return
        payload = {
            "player": self.player.get().strip()[:100],
            "total_files": self.total_files,
            "results": self.results[:MAX_RESULTS]
        }
        request = urllib.request.Request(
            endpoint + "/api/scan-results",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Scanner-Key": api_key},
            method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                result = json.loads(response.read().decode("utf-8"))
            self.root.after(0, self.log, f"تم إرسال التقرير بنجاح. رقم الفحص: {result.get('scan_id', '?')}")
            self.root.after(0, self.status.set, "تم إرسال التقرير إلى لوحة الإدارة.")
            self.root.after(0, messagebox.showinfo, APP_NAME, f"تم إرسال التقرير. رقم الفحص: {result.get('scan_id', '?')}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            self.root.after(0, self.log, f"فشل الإرسال HTTP {exc.code}: {detail}")
            self.root.after(0, messagebox.showerror, APP_NAME, f"تعذر إرسال التقرير (HTTP {exc.code}). تحقق من إعدادات الموقع ومفتاح API.")
        except Exception as exc:
            self.root.after(0, self.log, f"فشل الإرسال: {exc}")
            self.root.after(0, messagebox.showerror, APP_NAME, "تعذر الاتصال بالموقع. تحقق من الرابط والإنترنت.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
