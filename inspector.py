import os, json, time, random, hashlib, platform, subprocess, threading
from pathlib import Path
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox

REPORT_DIR = Path.home() / "Documents" / "3en_Inspector_Reports"

def new_run_id():
    return hashlib.sha256(f"{time.time_ns()}-{random.getrandbits(128)}".encode()).hexdigest()[:16].upper()

def check_defender():
    if os.name != "nt":
        return [{"check":"Defender","item":"Unavailable","detail":"Windows-only check","severity":"info"}]
    try:
        cmd = ["powershell.exe","-NoProfile","-NonInteractive","-Command",
               "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=12,
                           creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        data = json.loads(p.stdout.strip())
        off = [k for k in ("AMServiceEnabled","AntivirusEnabled","RealTimeProtectionEnabled") if data.get(k) is False]
        return [{"check":"Defender","item":"Microsoft Defender","detail":", ".join(off)+" disabled" if off else "Core protection reports enabled","severity":"review" if off else "info"}]
    except Exception:
        return [{"check":"Defender","item":"Status unavailable","detail":"Please verify in Windows Security","severity":"info"}]

def check_startup():
    results, roots = [], []
    for env in ("APPDATA","PROGRAMDATA"):
        value = os.environ.get(env)
        if value: roots.append(Path(value)/"Microsoft/Windows/Start Menu/Programs/Startup")
    for root in roots:
        try:
            for item in root.iterdir():
                if item.is_file():
                    results.append({"check":"Startup","item":str(item),"detail":"Startup-folder item; review if unfamiliar. Not proof of malware.","severity":"review"})
        except (OSError, PermissionError): pass
    return results

def check_temp():
    results, seen = [], set()
    for env in ("TEMP","TMP","LOCALAPPDATA"):
        value = os.environ.get(env)
        if not value: continue
        root = Path(value)/"Temp" if env == "LOCALAPPDATA" else Path(value)
        try:
            for item in root.iterdir():
                if not item.is_file() or item.suffix.lower() not in (".exe",".dll",".bat",".cmd",".ps1",".vbs",".js"): continue
                if str(item).lower() in seen: continue
                seen.add(str(item).lower())
                try:
                    age = (time.time()-item.stat().st_mtime)/3600
                    if age <= 72:
                        results.append({"check":"Temporary files","item":str(item),"detail":f"Recent executable/script-like file ({age:.1f} hours old). Not proof of malware.","severity":"review"})
                except OSError: pass
        except (OSError, PermissionError): pass
    return results[:500]

def check_processes():
    if os.name != "nt": return []
    try:
        p = subprocess.run(["tasklist","/FO","CSV","/NH"],capture_output=True,text=True,timeout=15,
                           creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        return [{"check":"Processes","item":line.split(",",1)[0].strip('"'),
                 "detail":"Observed process name; presence alone is not suspicious.","severity":"info"}
                for line in p.stdout.splitlines() if line][:1000]
    except Exception: return []

def perform_scan(progress):
    checks = [("حالة Windows Defender",check_defender),("مجلد بدء التشغيل",check_startup),
              ("الملفات الحديثة المؤقتة",check_temp),("العمليات الجارية",check_processes)]
    random.SystemRandom().shuffle(checks)
    results = []
    for i,(label,func) in enumerate(checks,1):
        progress(int((i-1)*100/len(checks)), "جاري الفحص: "+label)
        try: results.extend(func())
        except Exception as exc: results.append({"check":label,"item":"Error","detail":str(exc)[:200],"severity":"info"})
        progress(int(i*100/len(checks)), "اكتمل: "+label)
    return results

class Inspector:
    def __init__(self, root):
        self.root=root
        root.title("3en fight | 3en lnspector Team"); root.geometry("740x550"); root.minsize(620,460); root.configure(bg="#0b0b10")
        style=ttk.Style()
        try: style.theme_use("clam")
        except Exception: pass
        style.configure("TProgressbar",troughcolor="#252530",background="#e34242",thickness=18)
        tk.Label(root,text="3EN FIGHT",font=("Segoe UI",25,"bold"),fg="#ef4444",bg="#0b0b10").pack(pady=(16,0))
        tk.Label(root,text="3en lnspector Team  •  Windows Inspection",fg="#b8b8c5",bg="#0b0b10").pack(pady=(0,12))
        tk.Label(root,text="فحص محلي للقراءة فقط. لا يحذف ملفات أو يوقف عمليات ولا يرسل بيانات تلقائيًا.",wraplength=680,fg="#eee",bg="#0b0b10").pack(padx=20,pady=8)
        self.consent=tk.BooleanVar(value=False)
        tk.Checkbutton(root,text="أوافق على فحص هذا الجهاز وأفهم أن النتائج مؤشرات للمراجعة.",variable=self.consent,bg="#0b0b10",fg="#f3f4f6",selectcolor="#20202a",activebackground="#0b0b10",activeforeground="white",wraplength=680).pack(padx=20,pady=6)
        self.status=tk.Label(root,text="جاهز — وافق ثم اضغط بدء الفحص",fg="#b8b8c5",bg="#0b0b10"); self.status.pack(pady=(10,5))
        self.bar=ttk.Progressbar(root,maximum=100,length=650); self.bar.pack(padx=20,pady=5)
        self.pct=tk.Label(root,text="0%",fg="#ef4444",bg="#0b0b10",font=("Segoe UI",11,"bold")); self.pct.pack()
        self.btn=tk.Button(root,text="بدء الفحص",command=self.start,bg="#b91c1c",fg="white",activebackground="#dc2626",relief="flat",padx=22,pady=9,font=("Segoe UI",11,"bold")); self.btn.pack(pady=10)
        self.out=tk.Text(root,height=9,bg="#111118",fg="#e5e7eb",relief="flat",wrap="word"); self.out.pack(fill="both",expand=True,padx=20,pady=(2,14)); self.out.insert("end","سيظهر ملخص الفحص هنا.\n"); self.out.configure(state="disabled")
    def update_progress(self,value,label):
        self.root.after(0,lambda:(self.bar.configure(value=value),self.pct.configure(text=f"{value}%"),self.status.configure(text=label)))
    def start(self):
        if not self.consent.get():
            messagebox.showwarning("الموافقة مطلوبة","وافق على الفحص قبل البدء."); return
        self.btn.configure(state="disabled")
        threading.Thread(target=self.worker,daemon=True).start()
    def worker(self):
        rid=new_run_id(); results=perform_scan(self.update_progress)
        REPORT_DIR.mkdir(parents=True,exist_ok=True)
        report={"product":"3en lnspector Team","brand":"3en fight","run_id":rid,
                "created_at":datetime.now(timezone.utc).isoformat(),"device":platform.node(),
                "platform":platform.platform(),"check_order_randomized":True,"results":results,
                "notice":"Read-only heuristic results; review manually. Not a malware verdict."}
        path=REPORT_DIR/f"3en_inspection_{rid}.json"
        path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
        flagged=sum(1 for item in results if item.get("severity")=="review")
        summary=f"اكتمل الفحص بنسبة 100% ✓\nمعرّف الفحص: {rid}\nالعناصر المسجلة: {len(results)}\nعناصر تحتاج مراجعة: {flagged}\n\nحُفظ التقرير محليًا في:\n{path}\n\nالعناصر للمراجعة ليست دليلًا قاطعًا على وجود برمجية ضارة."
        self.root.after(0,lambda:self.finish(summary))
    def finish(self,summary):
        self.bar.configure(value=100); self.pct.configure(text="100%"); self.status.configure(text="اكتمل الفحص ✓")
        self.out.configure(state="normal"); self.out.delete("1.0","end"); self.out.insert("end",summary); self.out.configure(state="disabled")
        self.btn.configure(state="normal",text="إعادة الفحص"); messagebox.showinfo("اكتمل الفحص","اكتمل الفحص وحُفظ التقرير محليًا.")

if __name__=="__main__":
    root=tk.Tk(); Inspector(root); root.mainloop()
