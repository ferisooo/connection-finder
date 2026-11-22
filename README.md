# Connection Finder 💗🖤

A pink & black Windows app that shows **which IP addresses are connected to your PC**, **which program** is behind each one (its **folder** and **file name**), and **warns you about suspicious ones**. You can also ask your own AI (ChatGPT, Claude, Gemini, DeepSeek, Grok, Mistral, OpenRouter or a local AI) for a second opinion.

![Connection Finder screenshot (demo data)](test/screenshots/home.png)

## What it does

- **One sentence at the top tells you what's going on.** For example: *"2 programs look dangerous. They're at the top of the list. Each card tells you why."* or *"Everything looks safe right now."*
- **One card per program** shows its file name, the folder it runs from, and who it's talking to (IP address, country and owner).
- **Every card answers "Is it suspicious?"**
  - **Yes:** it lists why in plain words, for example *"Runs from a Temp folder. Temp is for throwaway files. Real apps rarely run from there."*
  - **No:** it says why it looks safe, for example *"Made by Google LLC (signed) · Installed in Program Files · Secure connection (port 443)"*.
- **Colors:** grey = looks safe, pink = suspicious, glowing pink = danger. 20+ warning points means suspicious, 50+ means danger.
- **Things it checks:** sneaky folders (Temp, Downloads, Recycle Bin, hidden Windows folders), missing or broken digital signatures, fake Windows names (`svch0st.exe`), Windows tools that hackers misuse, hidden or encoded start-up commands, fake document names (`invoice.pdf.exe`), hacker / Tor / crypto-mining / remote-control ports, VPN or proxy IPs, and countries you choose to flag.
- **Ask AI:** one click sends a program's details to *your* AI, using *your* API key, for a second opinion.
- **Quick actions:** open the program's folder, stop the program, or open **Details**, which has everything (technical bits are tucked away at the bottom).
- **Help** button (top right) explains everything in simple words. Text is at least 15px everywhere.
- Updates live every few seconds. Click the **Live** pill to pause.

## Download & run (no coding needed)

1. Open this repository on GitHub and click the **Actions** tab.
2. Click the newest **Build Windows app** run that has a green check ✅.
3. Scroll down to **Artifacts** and download **ConnectionFinder-Windows** (a zip file).
4. Unzip it anywhere (for example into `Documents\Connection Finder`), and double-click **ConnectionFinder.exe**.
5. Windows might say *"Windows protected your PC"*, because the app isn't signed by a company. Click **More info → Run anyway**.

**Tip:** Some programs' folders are hidden unless the app runs as administrator. Click **Restart as admin** in the app, or right-click `ConnectionFinder.exe` → **Run as administrator**.

## Setting up the AI helper

1. Click the ⚙️ **Settings** button (top right).
2. Pick your **AI company** and paste your **API key**, then click **Save key**.
3. Optional: click **Choose model** to pick from the models your key can use.
4. Click **Test connection** to make sure it works.

Your key is stored in the Windows Credential Manager on your PC. Nothing is sent to the AI until you press an **Ask AI** button. Then the app sends that connection's IP, the program's folder and file name, its start-up command and the app's clues.

The **IP lookup** (country and owner) uses the free ip-api.com service and sends only public IP addresses. You can switch it off in Settings.

> A warning is a clue, not proof of malware. When unsure, ask the AI, search for the program's name online, or scan it with Windows Security.

## For developers

Built with Flutter (Windows desktop).

```bash
flutter pub get
```

```bash
flutter test
```

```bash
flutter build windows --release
```

- `lib/services/scanner.dart`: reads connections, processes and signatures with PowerShell (`Get-NetTCPConnection`, `Get-NetUDPEndpoint`, `Win32_Process`, `Get-AuthenticodeSignature`), with `netstat -ano` as a backup.
- `lib/services/process_path.dart`: asks Windows (kernel32 `QueryFullProcessImageNameW`) for program paths that PowerShell can't see.
- `lib/services/risk_engine.dart`: the suspicion clues and points.
- `lib/services/ai_service.dart`: OpenAI-compatible, Claude (Messages API) and Gemini requests.
- `lib/services/geo_service.dart`: IP country/owner lookup.
- On non-Windows computers the app shows made-up **demo data**, which is also used for the screenshots (`CF_SCREENSHOTS=1 flutter test --update-goldens test/screenshot_test.dart`).

Every push builds the app on GitHub's Windows machines (`.github/workflows/build-windows.yml`). That build also runs a real connection scan as a test.
