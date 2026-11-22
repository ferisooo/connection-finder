# Connection Finder 💗🖤

A pink & black Windows app that shows **which IP addresses are connected to your PC**, **which program** is behind each one (its **folder** and **file name**), and **warns you about suspicious ones**. You can also ask your own AI (ChatGPT, Claude, Gemini, DeepSeek, Grok, Mistral, OpenRouter or a local AI) for a second opinion.

<p align="center">
  <a href="https://github.com/ferisooo/connection-finder/releases/latest/download/ConnectionFinder-Setup.exe">
    <img alt="Download for Windows" src="https://img.shields.io/badge/Download%20for%20Windows-ConnectionFinder--Setup.exe-ff4fa3?style=for-the-badge&logo=windows&logoColor=white&labelColor=111117" height="44">
  </a>
</p>

<p align="center"><b>Click the pink button, open the file, click Install. That's it!</b></p>

![Connection Finder screenshot (demo data)](test/screenshots/home.png)

## What it does

- **One sentence at the top tells you what's going on.** For example: *"2 programs look dangerous. They're at the top of the list. Each card tells you why."* or *"Everything looks safe right now."*
- **Only what needs a look is shown.** Trusted programs (signed by a known company, installed normally, no warning signs) stay hidden. You only see a card for a program that looks suspicious, or one Windows wouldn't let the app check.
- **Every card answers "Is it suspicious?"** with the reasons in plain words, for example *"Runs from a Temp folder. Temp is for throwaway files. Real apps rarely run from there."*
- **"Couldn't check"** means Windows hid the program from the app (it runs with higher rights). That's usually a Windows service, but the app says so honestly instead of calling it safe. **Restart as admin** checks those too.
- **Colors:** pink = suspicious, glowing pink = danger, grey = couldn't check. 20+ warning points means suspicious, 50+ means danger.
- **Things it checks about the program:** sneaky folders (Temp, Downloads, Recycle Bin, hidden Windows folders), missing or broken digital signatures, fake Windows names (`svch0st.exe`), Windows tools that hackers misuse, hidden or encoded start-up commands, fake document names (`invoice.pdf.exe`).
- **Unusual behavior it points out:**
  - **Who started it:** a document app (Word, Excel, a PDF reader...) that starts a command tool which then goes online.
  - **Starting by itself:** an unsigned program that starts with Windows through the startup list, the Startup folder, a scheduled task or a service, especially one that was added recently.
  - **Remote control:** remote-control apps (AnyDesk, TeamViewer, Quick Assist...), Remote Desktop being switched on, or someone connected to it. The card explains that this is fine if you set it up yourself.
  - **Clockwork calls:** a program that contacts the same address on a timer ("phoning home").
  - **New programs:** an unsigned program that Connection Finder sees online for the first time.
  - **Distrusted destinations:** hacker / Tor / crypto-mining ports, VPN or proxy addresses, countries you flag, and addresses on a public list of addresses reported for attacks ([IPsum](https://github.com/stamparm/ipsum), downloaded once a day; nothing about your PC is sent).
- **It explains, it doesn't remove.** Connection Finder never deletes or blocks anything. Virus scanning and blocking stay with Windows Security (or your antivirus). In **Details** there is a **Scan with Windows Security** button that hands the file to Windows Defender.
- **Ask AI:** one click sends a program's details to *your* AI, using *your* API key, for a second opinion.
- **Quick actions:** open the program's folder, stop the program, or open **Details**, which has everything (technical bits are tucked away at the bottom).
- **Test the alarm:** in Settings, **Start fake virus** runs a harmless test program for 3 minutes (`tool/fake_virus.dart`). It reads, logs and sends nothing; it only tries to reach reserved test addresses that belong to nobody, from the Temp folder, unsigned, on "hacker" port 4444, with a "phone home" every 20 seconds. Connection Finder should flag it as **Danger!** within seconds.
- **Help** button (top right) explains everything in simple words. Text is at least 15px everywhere.
- Updates live every few seconds. Click the **Live** pill to pause.

## Download & install

1. Click the pink **Download for Windows** button at the top of this page.
2. Open the downloaded **ConnectionFinder-Setup.exe** and click **Install**.
3. Connection Finder opens by itself. Next time, use the shortcut on your desktop or in the Start menu.

If Windows says *"Windows protected your PC"*, click **More info**, then **Run anyway**. It says that because the app is new and isn't signed by a company.

**Tip:** to see every program's folder, click **Restart as admin** inside the app.

The download always has the newest version. It updates by itself whenever changes land on `main` and all tests pass. To uninstall, use Windows Settings, Apps, like any other program.

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
- `lib/services/repeat_tracker.dart`, `seen_store.dart`, `bad_addresses.dart`: clockwork calls, what is new, and the reported-address list.
- `lib/services/ai_service.dart`: OpenAI-compatible, Claude (Messages API) and Gemini requests.
- `lib/services/geo_service.dart`: IP country/owner lookup.
- On non-Windows computers the app shows made-up **demo data**, which is also used for the screenshots (`CF_SCREENSHOTS=1 flutter test --update-goldens test/screenshot_test.dart`).

Every push builds the app on GitHub's Windows machines (`.github/workflows/build-windows.yml`), runs all tests (including a real connection scan on Windows) and makes the installer (`windows/installer/connection_finder.iss`, Inno Setup). Pushes to `main` that pass publish the installer on the Releases page, which the download button points to.
