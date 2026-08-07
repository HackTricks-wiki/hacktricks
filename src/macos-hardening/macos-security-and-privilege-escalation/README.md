# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic MacOS

यदि आप macOS से परिचित नहीं हैं, तो आपको macOS की मूल बातें सीखना शुरू करना चाहिए:

- विशेष macOS **files & permissions:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- सामान्य macOS **users**


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- k**ernel** का **architecture**


{{#ref}}
mac-os-architecture/
{{#endref}}

- सामान्य macOS n**etwork services & protocols**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- `tar.gz` डाउनलोड करने के लिए [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) जैसे URL को [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) में बदलें

### MacOS MDM

कंपनियों में **macOS** systems के **MDM से managed** होने की बहुत अधिक संभावना होती है। इसलिए, एक attacker के दृष्टिकोण से यह जानना उपयोगी है कि यह **कैसे काम करता है**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspecting, Debugging and Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Security Protections


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

यदि **root के रूप में चल रहा process** ऐसी file **लिखता है** जिसे user नियंत्रित कर सकता है, तो user इसका दुरुपयोग करके **privileges escalate** कर सकता है।\
यह निम्नलिखित परिस्थितियों में हो सकता है:

- उपयोग की गई file पहले से ही user द्वारा बनाई गई थी (user के ownership में)
- उपयोग की गई file user द्वारा writable है क्योंकि वह किसी group से संबंधित है
- उपयोग की गई file user के ownership वाली directory के अंदर है (user file बना सकता है)
- उपयोग की गई file root के ownership वाली directory के अंदर है, लेकिन user के पास किसी group के कारण उस पर write access है (user file बना सकता है)

ऐसी **file create करने** में सक्षम होना जिसे **root उपयोग करने वाला है**, user को उसके content का **फायदा उठाने** या उसे किसी अन्य स्थान पर point करने के लिए **symlinks/hardlinks** बनाने की अनुमति देता है।

इस प्रकार की vulnerabilities के लिए **vulnerable `.pkg` installers** को **check** करना न भूलें:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

File extensions द्वारा registered अजीब apps का दुरुपयोग किया जा सकता है और specific protocols को open करने के लिए अलग-अलग applications को register किया जा सकता है


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

macOS में **applications और binaries के पास folders या settings access करने की permissions हो सकती हैं**, जिससे वे अन्य applications की तुलना में अधिक privileged हो जाते हैं।

इसलिए, macOS machine को सफलतापूर्वक compromise करने के इच्छुक attacker को अपनी **TCC privileges escalate** करनी होंगी (या अपनी आवश्यकता के अनुसार **SIP bypass** भी करना पड़ सकता है)।

ये privileges आमतौर पर उन **entitlements** के रूप में दी जाती हैं जिनके साथ application signed होती है, या application कुछ accesses request कर सकती है और **user द्वारा उन्हें approve करने** के बाद वे **TCC databases** में पाई जा सकती हैं। कोई process इन privileges को प्राप्त करने का एक अन्य तरीका यह है कि वह उन **privileges** वाले process का **child** हो, क्योंकि वे आमतौर पर **inherited** होती हैं।<sup>[[5]](#references)</sup>

विभिन्न तरीकों से [**escalate privileges in TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), [**bypass TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) करने और अतीत में [**SIP has been bypassed**](macos-security-protections/macos-sip.md#sip-bypasses) के बारे में जानने के लिए इन links को follow करें।

## macOS Traditional Privilege Escalation

बेशक, red teams के दृष्टिकोण से आपको root तक escalate करने में भी रुचि होनी चाहिए। कुछ hints के लिए निम्नलिखित post देखें:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
