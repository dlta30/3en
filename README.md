# 3EN FIGHT — INSPECTOR TEAM

Standalone Windows inspection utility with a black/red desktop interface.

## What it currently checks

- Microsoft Defender protection status.
- Running process names, executable paths and command lines for generic review terms sometimes associated with game cheats/injectors.
- Windows startup entries and Startup-folder items.
- Recently modified executable/script-like files in the current user's temporary folders (up to 72 hours), with local SHA-256 hashes.
- Optional user-triggered Microsoft Defender Quick Scan.
- A local JSON report with UTC timestamp, run ID, findings and limitations.

## Important limitations

- This is a defensive review tool, not a guarantee that every cheat, malware family or hidden component will be detected.
- A process name or keyword match is only a lead for manual review; it is not proof of cheating.
- The tool does not terminate processes, delete files, disable security controls, hide itself, bypass anti-cheat, or automatically upload reports/file contents.
- Reports are saved locally under Documents/3EN_FIGHT_Reports. Use Export JSON to copy a report elsewhere.
- Defender's own scan results remain authoritative in Windows Security.

## Build the Windows EXE

A GitHub Actions workflow builds the EXE on Windows:

1. Open the repository's Actions tab.
2. Select Build 3EN FIGHT Inspector EXE.
3. Click Run workflow (or open the latest run triggered by a push).
4. Wait for the build to finish successfully.
5. Download the artifact named 3EN-FIGHT-INSPECTOR-Windows from the completed workflow run. It contains 3EN_FIGHT_INSPECTOR.exe.

The artifact is a build output, not a signed installer. Windows SmartScreen or antivirus may show warnings for unsigned/self-built binaries. Do not disable protection to run it; inspect the source and build logs first.

## Build locally (Windows)

Install Python 3.12, then run:

```powershell
python -m py_compile inspector.py
python -m pip install --upgrade pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name 3EN_FIGHT_INSPECTOR inspector.py
```

The EXE will be created in dist/3EN_FIGHT_INSPECTOR.exe.

## Consent and privacy

Run this only on a device you own or have explicit permission to inspect. The user must check the consent box before a scan begins. The current desktop version keeps reports on that device and does not connect to the website/archive backend.
