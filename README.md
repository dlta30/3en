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
- The tool does not terminate processes, delete files, disable security controls, hide itself, or bypass anti-cheat.
- A separate explicit checkbox is required to consent to a full-screen screenshot being captured and sent with the report to the configured Discord webhook. Do not run this on another person's device without their informed permission.
- Set `DISCORD_WEBHOOK_URL` in the environment before launching the app. Never hardcode a webhook URL into source code or distribute it inside the EXE; anyone with the URL can post to that Discord channel.
- Reports and consented screenshots are saved locally under Documents/3EN_FIGHT_Reports. The Discord message includes a summary, JSON report, and screenshot if capture succeeds. Screenshot capture is optional; a local scan does not require screenshot consent.
- Optional Render dashboard upload uses `INSPECTOR_API_URL` (your Render service base URL, for example `https://your-service.onrender.com`) and `SCANNER_API_KEY` on the computer running the desktop app. On Render, set the same `SCANNER_API_KEY` and set `DISCORD_WEBHOOK_URL` to the new Discord webhook. The server saves the report in the owner dashboard and forwards a summary plus JSON report attachment to Discord. The desktop app appends `/api/scan-results` automatically. Keep the API key and webhook private; do not publish them or bake them into a public EXE.
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
python -m pip install --upgrade pyinstaller pillow
pyinstaller --noconfirm --clean --onefile --windowed --name 3EN_FIGHT_INSPECTOR inspector.py
```

The EXE will be created in dist/3EN_FIGHT_INSPECTOR.exe.

## Consent and privacy

Run this only on a device you own or have explicit permission to inspect. The user must check the consent box before a scan begins. The desktop version keeps a local JSON report and can optionally submit a minimized summary to the website using `INSPECTOR_API_URL` and `SCANNER_API_KEY`. The website stores the sanitized scan details submitted by the desktop client. The Render server forwards the report JSON to Discord when `DISCORD_WEBHOOK_URL` is configured. Full-screen screenshots remain optional and are sent only when the device user explicitly checks the screenshot-consent box and the desktop client has a Discord webhook configured locally; the Render forwarding path does not receive screenshots.
